package oidc

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"

	"github.com/dexidp/dex/storage"
	"github.com/pkg/errors"

	"github.com/dexidp/dex/connector"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
	istorage "github.com/lstoll/idp/storage"
	"github.com/lstoll/idp/storage/storagepb"
)

// ConnectorID is what this connector should be named in dex.
const ConnectorID = "idp"

type DexConnector struct {
	// Wrapped is the idp connector we delegate access to
	Wrapped idp.Connector
	// Prefix is the URL prefix dex is running on, used for redirects
	Prefix string
	// DexStore gives us access to dex's state
	DexStore storage.Storage
	// IDPStore give us access to our storage interface
	IDPStore storagepb.StorageClient
}

/************
* dex side
************/

func (d *DexConnector) Open(id string, logger logrus.FieldLogger) (connector.Connector, error) {
	return d, nil
}

// LoginURL returns the URL to redirect the user to login with.
func (d *DexConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	// just return out connector-fronting page.
	v := url.Values{}
	v.Set("state", state)
	return fmt.Sprintf("/oidclogin/%s?%s", ConnectorID, v.Encode()), nil
}

// HandleCallback parses the request and returns the user's identity
func (d *DexConnector) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {
	log.Print("Starting handle callback")
	authID := r.URL.Query().Get("state")
	if authID == "" {
		return connector.Identity{}, errors.New("state param not provided")
	}

	// for the given state parameter on the callback, look up the identity
	// in the storage, and then return it.

	gresp, err := d.IDPStore.Get(r.Context(), &storagepb.GetRequest{Keyspace: "oidc-authed-identity", Keys: []string{authID}})
	if err != nil {
		return connector.Identity{}, errors.Wrap(err, "Error getting request state")
	}
	// unmarshal
	oa := idppb.OIDCAuthorization{}
	if err := ptypes.UnmarshalAny(gresp.Items[0].Object, &oa); err != nil {
		return connector.Identity{}, errors.Wrap(err, "Error unpacking any")
	}

	log.Print("Handle callback about to return identity")

	return connector.Identity{
		UserID: oa.Identity.UserId,
		//Email:         "",
		EmailVerified: true,
	}, nil
}

/************
* our side - connector
************/

func (d *DexConnector) loginHandler(w http.ResponseWriter, r *http.Request) {
	authIDs := r.URL.Query()["state"]
	if len(authIDs) != 1 {
		http.Error(w, "State not provided", http.StatusBadRequest)
		return
	}

	ar, err := d.DexStore.GetAuthRequest(authIDs[0])
	if err != nil {
		http.Error(w, "Error looking up auth request", http.StatusInternalServerError)
		return
	}

	lr := idp.LoginRequest{
		SSOMethod: idp.SSOMethodOIDC,
		AuthID:    authIDs[0],
		ClientID:  ar.ClientID,
		Scopes:    ar.Scopes,
	}

	d.Wrapped.LoginPage(w, r, lr)
}

/************
* our side - authenticator
************/

func (d *DexConnector) Authenticate(authID string, ident idppb.Identity) (returnURL string, err error) {
	// authID == state

	etime := time.Now().Add(1 * time.Hour)
	exp, err := ptypes.TimestampProto(etime)
	if err != nil {
		panic(err)
	}

	auth := &idppb.OIDCAuthorization{
		Identity: &ident,
		Expires:  exp,
	}
	mreq, err := istorage.PutMutation("oidc-authed-identity", authID, auth, &etime)
	if err != nil {
		return "", errors.Wrap(err, "Error building put mutation")
	}
	if _, err := d.IDPStore.Mutate(context.TODO(), mreq); err != nil {
		return "", errors.Wrap(err, "Error storing state")
	}

	// The returned URL is ( dex issuer URL )/callback/( connector id )?( url query )
	// ref: https://github.com/dexidp/dex/blob/master/Documentation/connectors/authproxy.md

	return "/callback/" + ConnectorID + "?state=" + authID, nil
}
