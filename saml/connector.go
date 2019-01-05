package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/gorilla/sessions"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
	"github.com/pkg/errors"
)

const sessionMaxAge = 24 * time.Hour

type Connector struct {
	// IDPStore give us access to our storage interface
	IDPStore idp.Storage
	Wrapped  idp.Connector
}

/************
* SAML provider side - implements saml.SessionProvider
*************/

func (d *Connector) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	// check params for ?authid=authid. If so, check the auth is valid and create the session

	if r.URL.Query().Get("authid") != "" {
		ab, err := d.IDPStore.Get("saml-authed-identity", r.URL.Query().Get("authid"))
		if err != nil {
			if d.IDPStore.ErrIsNotFound(err) {
				http.Error(w, "Unauthorized Session", http.StatusForbidden)
				return nil
			}
			http.Error(w, "Error reading state", http.StatusInternalServerError)
			return nil
		}

		// unmarshal
		oa := idppb.SAMLAuthorization{}
		if err := proto.Unmarshal(ab, &oa); err != nil {
			http.Error(w, "Error unmarshaling auth", http.StatusInternalServerError)
			return nil
		}

		// TODO - check validity, then delete either way

		session := &saml.Session{
			ID:             base64.StdEncoding.EncodeToString(randomBytes(32)),
			CreateTime:     saml.TimeNow(),
			ExpireTime:     saml.TimeNow().Add(sessionMaxAge),
			Index:          hex.EncodeToString(randomBytes(32)),
			UserName:       oa.Identity.UserId,
			Groups:         []string{"user.Groups[:]"},
			UserEmail:      "user.Email",
			UserCommonName: "user.CommonName",
			UserSurname:    "user.Surname",
			UserGivenName:  "user.GivenName",
		}

		if !oa.Authorized {
			http.Error(w, "Unauthorized Session", http.StatusForbidden)
			return nil
		}

		// TODO - do we need to store this session and track it by cookie? or is each SSO just a new session?
		return session
	}

	// create the login record, prep it to store for validation
	authID := base64.StdEncoding.EncodeToString(randomBytes(32))

	exp, _ := ptypes.TimestampProto(time.Now().Add(1 * time.Hour))
	sa := &idppb.SAMLAuthorization{
		Expires:     exp,
		SamlRequest: req.RequestBuffer,
		RelayState:  req.RelayState,
	}
	sab, err := proto.Marshal(sa)
	if err != nil {
		http.Error(w, "Error marshaling auth", http.StatusInternalServerError)
		return nil
	}
	if err := d.IDPStore.Put("saml-authed-identity", authID, sab); err != nil {
		http.Error(w, "Error storing state", http.StatusInternalServerError)
		return nil
	}

	d.Wrapped.LoginPage(w, r, idp.LoginRequest{
		AuthID:    authID, // I don't think this actually matters - the idp code is already tracking sessions
		SSOMethod: idp.SSOMethodSAML,
	})

	return nil
}

/************
* our side - Authenticator
************/

func (d *Connector) Authenticate(authID string, ident idppb.Identity) (returnURL string, err error) {
	// Mark the authid successful in the data store

	// return a URL for a "finalize" page. this page needs to securely know if
	// the session is good or not. could do this by the mark in the DB?
	// NOTE - this finalize page could just be "/sso" / GetSession

	sab, err := d.IDPStore.Get("saml-authed-identity", authID)
	if err != nil {
		return "", errors.Wrap(err, "Error getting identity to authenticate")
	}

	sa := &idppb.SAMLAuthorization{}
	if err := proto.Unmarshal(sab, sa); err != nil {
		return "", errors.Wrapf(err, "Error unmarshaling authID %q", authID)
	}

	sa.Identity = &ident
	sa.Authorized = true

	sab, err = proto.Marshal(sa)
	if err != nil {
		return "", errors.Wrap(err, "Error marshaling identity")
	}

	if err := d.IDPStore.Put("saml-authed-identity", authID, sab); err != nil {
		return "", errors.Wrap(err, "Error storing state")
	}

	// The returned URL is ( dex issuer URL )/callback/( connector id )?( url query )
	// ref: https://github.com/dexidp/dex/blob/master/Documentation/connectors/authproxy.md

	uv := url.Values{}
	uv.Add("authid", authID)
	uv.Add("RelayState", sa.RelayState)
	// need to compress, then base64 this

	buf := &bytes.Buffer{}
	compressor, err := flate.NewWriter(buf, flate.DefaultCompression)
	if err != nil {
		return "", errors.Wrap(err, "error creating deflator")
	}
	if _, err := compressor.Write(sa.SamlRequest); err != nil {
		return "", errors.Wrap(err, "Error compressing SAML request")
	}
	if err := compressor.Close(); err != nil {
		return "", errors.Wrap(err, "Error closing deflator")
	}

	uv.Add("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
	return "/sso?" + uv.Encode(), nil
}

// func (d *Connector) Finalize(w http.ResponseWriter, r *http.Request) {
// 	// This is the "final" page

// 	// THIS SHOULD IMPLEMENT MOST OF GetSession. In fact, it could probably be merged there much like upstream?

// 	// look up the auth in the DB. Delete it after to prevent replays

// 	// is it bad? fail

// 	// is it good? set up the session record and cookie like upstream does https://github.com/crewjam/saml/blob/bb12e77/samlidp/session.go#L49-L74

// 	// redirect to that very upstream page. It should fall to the "check cookie" case and finalize the session
// }

// Session store, can be used for connector specific cookie state. Need to
// call Save() if modified
func (d *Connector) Session(r *http.Request) sessions.Store {
	return nil // TODO - look up on dex
}

// Storage can be used for persistent state
func (d *Connector) Storage() idp.Storage {
	panic("todo - need to bolt storage onto this somehow")
}

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}
