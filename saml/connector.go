package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/lstoll/idp/storage"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lstoll/idp/storage/storagepb"

	"github.com/crewjam/saml"
	"github.com/golang/protobuf/ptypes"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
	"github.com/pkg/errors"
)

const (
	sessionMaxAge = 24 * time.Hour
	samlFlowNS    = "saml-authed-identity"
)

type Connector struct {
	// Cache give us access to our transient storage
	Storage storagepb.StorageClient
	Wrapped idp.Connector
}

/************
* SAML provider side - implements saml.SessionProvider
*************/

func (d *Connector) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	// check params for ?authid=authid. If so, check the auth is valid and create the session

	if r.URL.Query().Get("authid") != "" {
		aidReq := &storagepb.GetRequest{Keyspace: samlFlowNS, Keys: []string{r.URL.Query().Get("authid")}}
		aidResp, err := d.Storage.Get(r.Context(), aidReq)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "Unauthorized Session", http.StatusForbidden)
				return nil
			}
			http.Error(w, "Error reading state", http.StatusInternalServerError)
			return nil
		}

		// unmarshal
		oa := idppb.SAMLAuthorization{}
		if err := ptypes.UnmarshalAny(aidResp.Items[0].Object, &oa); err != nil {
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

	sa := &idppb.SAMLAuthorization{
		SamlRequest: req.RequestBuffer,
		RelayState:  req.RelayState,
	}
	exp := time.Now().Add(15 * time.Minute)
	mreq, err := storage.PutMutation(samlFlowNS, authID, sa, &exp)
	if err != nil {
		http.Error(w, "Error building mutation", http.StatusInternalServerError)
		return nil
	}
	if _, err := d.Storage.Mutate(r.Context(), mreq); err != nil {
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

	sab, err := d.Storage.Get(context.TODO(), &storagepb.GetRequest{Keyspace: "saml-authed-identity", Keys: []string{authID}})
	if err != nil {
		return "", errors.Wrap(err, "Error getting identity to authenticate")
	}
	sa := &idppb.SAMLAuthorization{}
	if err := ptypes.UnmarshalAny(sab.Items[0].Object, sa); err != nil {
		return "", errors.Wrapf(err, "Error unmarshaling authID %q", authID)
	}

	sa.Identity = &ident
	sa.Authorized = true

	et, _ := ptypes.Timestamp(sab.Items[0].Expires)
	sm, err := storage.PutMutation(samlFlowNS, authID, sa, &et)
	if err != nil {
		return "", errors.Wrap(err, "Error marshaling identity")
	}

	if _, err := d.Storage.Mutate(context.TODO(), sm); err != nil {
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

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}
