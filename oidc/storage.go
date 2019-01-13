package oidc

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/golang/protobuf/ptypes"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	istorage "github.com/lstoll/idp/storage"
	"github.com/lstoll/idp/storage/storagepb"

	"github.com/dexidp/dex/storage"
	"github.com/lstoll/idp/idppb"
	"github.com/pkg/errors"
)

const (
	authCodeNS       = "dex-auth-code"
	refreshTokenNS   = "dex-refresh-token"
	authRequestNS    = "dex-auth-request"
	offlineSessionNS = "dex-offline-session"
	keysNS           = "dex-keys"

	keysKey = "keys"
)

var _ storage.Storage = (*dstorage)(nil)

type dstorage struct {
	Storage      storagepb.StorageClient
	clientLookup func(clientID string) (client *idppb.OIDCClient, ok bool, err error)
}

func (d *dstorage) Close() error { return nil }

func (d *dstorage) GarbageCollect(now time.Time) (result storage.GCResult, err error) {
	// TODO - do we care about this, or should we just be smart about setting expires keys?
	return result, nil
}

func (d *dstorage) createInNS(namespace, itemID string, item interface{}, expiry *time.Time) error {
	_, err := d.Storage.Get(context.TODO(), &storagepb.GetRequest{Keyspace: namespace, Keys: []string{itemID}})
	if err == nil { // got the item successfully, dupe!
		return storage.ErrAlreadyExists
	} else if err != nil && status.Code(err) != codes.NotFound { // we have an actual error
		return errors.Wrapf(err, "Error checking for existence of item %q in namespace %q", itemID, namespace)
	}

	ib, err := json.Marshal(item)
	if err != nil {
		return errors.Wrapf(err, "Error marshaling item %q in namespace %q", itemID, namespace)
	}
	im := &storagepb.Bytes{Data: ib}
	mreq, err := istorage.PutMutation(namespace, itemID, im, expiry)
	if err != nil {
		return errors.Wrap(err, "Error building mutation")
	}
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrapf(err, "Error storing item %q in namespace %q", itemID, namespace)
	}
	return nil
}

func (d *dstorage) getFromNS(namespace, itemID string, into interface{}) error {
	gresp, err := d.Storage.Get(context.TODO(), &storagepb.GetRequest{Keyspace: namespace, Keys: []string{itemID}})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return storage.ErrNotFound
		}
		return errors.Wrapf(err, "Error getting item %q from namespace %q", itemID, namespace)
	}
	bm := &storagepb.Bytes{}
	if err := ptypes.UnmarshalAny(gresp.Items[0].Object, bm); err != nil {
		return errors.Wrap(err, "Error unmarshaling any")
	}
	if err := json.Unmarshal(bm.Data, into); err != nil {
		return errors.Wrapf(err, "Error json unmarshaling item %q from namespace %q", itemID, namespace)
	}
	return nil
}

func (d *dstorage) CreateClient(c storage.Client) error {
	panic("not supported")
}

func (d *dstorage) CreateAuthCode(a storage.AuthCode) (err error) {
	return d.createInNS(authCodeNS, a.ID, &a, &a.Expiry)
}

func (d *dstorage) CreateRefresh(r storage.RefreshToken) (err error) {
	return d.createInNS(refreshTokenNS, r.ID, &r, nil) // TODO - some kind of expiry?
}

func (d *dstorage) CreateAuthRequest(a storage.AuthRequest) (err error) {
	return d.createInNS(authRequestNS, a.ID, &a, &a.Expiry)
}

func (d *dstorage) CreatePassword(p storage.Password) (err error) {
	panic("not supported")
}

func (d *dstorage) CreateOfflineSessions(o storage.OfflineSessions) (err error) {
	return d.createInNS(authRequestNS, o.ConnID+"-"+o.UserID, &o, nil)
}

func (d *dstorage) CreateConnector(connector storage.Connector) (err error) {
	panic("not supported")
}

func (d *dstorage) GetAuthCode(id string) (c storage.AuthCode, err error) {
	if err := d.getFromNS(authCodeNS, id, &c); err != nil {
		return c, err
	}
	return c, nil
}

func (d *dstorage) GetPassword(email string) (p storage.Password, err error) {
	panic("not supported")
}

func (d *dstorage) GetClient(id string) (client storage.Client, err error) {
	log.Printf("Get client called with %q", id)
	cl, ok, err := d.clientLookup(id)
	if err != nil {
		return client, errors.Wrap(err, "Error looking up client")
	}
	if !ok {
		return client, storage.ErrNotFound
	}
	return storage.Client{
		ID:           cl.Id,
		Secret:       cl.Secret,
		RedirectURIs: cl.RedirectUris,
		TrustedPeers: cl.TrustedPeers,
		Public:       cl.Public,
		Name:         cl.Name,
		LogoURL:      cl.LogoUrl,
	}, nil
}

func (d *dstorage) GetKeys() (keys storage.Keys, err error) {
	if err := d.getFromNS(keysNS, keysKey, &keys); err != nil {
		return keys, err
	}
	return keys, nil
}

func (d *dstorage) GetRefresh(id string) (tok storage.RefreshToken, err error) {
	if err := d.getFromNS(refreshTokenNS, id, &tok); err != nil {
		return tok, err
	}
	return tok, nil

}

func (d *dstorage) GetAuthRequest(id string) (req storage.AuthRequest, err error) {
	if err := d.getFromNS(authRequestNS, id, &req); err != nil {
		return req, err
	}
	return req, nil

}

func (d *dstorage) GetOfflineSessions(userID string, connID string) (o storage.OfflineSessions, err error) {
	if err := d.getFromNS(offlineSessionNS, connID+"-"+userID, &o); err != nil {
		return o, err
	}
	return o, nil

}

func (d *dstorage) GetConnector(id string) (connector storage.Connector, err error) {
	panic("not supported")
}

func (d *dstorage) ListClients() (clients []storage.Client, err error) {
	panic("TODO - pull from wrapped")
}

func (d *dstorage) ListRefreshTokens() (tokens []storage.RefreshToken, err error) {
	lresp, err := d.Storage.ListKeys(context.TODO(), &storagepb.ListRequest{Keyspace: refreshTokenNS})
	if err != nil {
		return nil, errors.Wrap(err, "Error listing refresh token keys")
	}
	gresp, err := d.Storage.Get(context.TODO(), &storagepb.GetRequest{Keyspace: refreshTokenNS, Keys: lresp.Keys})
	if err != nil {
		return nil, errors.Wrap(err, "Error fetching all current refresh tokens")
	}
	for _, ri := range gresp.Items {
		bm := storagepb.Bytes{}
		if err := ptypes.UnmarshalAny(ri.Object, &bm); err != nil {
			return nil, errors.Wrap(err, "Error unmarshaling any")
		}
		rt := storage.RefreshToken{}
		if err := json.Unmarshal(bm.Data, &rt); err != nil {
			return nil, errors.Wrap(err, "Error unmarshaling json")
		}
		tokens = append(tokens, rt)
	}
	return tokens, nil
}

func (d *dstorage) ListPasswords() (passwords []storage.Password, err error) {
	panic("not supported")
}

func (d *dstorage) ListConnectors() (conns []storage.Connector, err error) {
	// TODO - implement the "static" connectors functionality directly here?
	return conns, err
}

func (d *dstorage) DeletePassword(email string) (err error) {
	panic("not supported")
}

func (d *dstorage) DeleteClient(id string) (err error) {
	panic("not supported")
}

func (d *dstorage) DeleteRefresh(id string) (err error) {
	mreq := istorage.DeleteMutation(refreshTokenNS, id)
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", id, refreshTokenNS)
	}
	return nil
}

func (d *dstorage) DeleteAuthCode(id string) (err error) {
	mreq := istorage.DeleteMutation(authCodeNS, id)
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", id, authCodeNS)
	}
	return nil
}

func (d *dstorage) DeleteAuthRequest(id string) (err error) {
	mreq := istorage.DeleteMutation(authRequestNS, id)
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", id, authRequestNS)
	}
	return nil
}

func (d *dstorage) DeleteOfflineSessions(userID string, connID string) (err error) {
	mreq := istorage.DeleteMutation(offlineSessionNS, connID+"-"+userID)
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", connID+"-"+userID, offlineSessionNS)
	}
	return nil
}

func (d *dstorage) DeleteConnector(id string) (err error) {
	panic("not supported")
}

func (d *dstorage) UpdateClient(id string, updater func(old storage.Client) (storage.Client, error)) (err error) {
	panic("not supported")
}

func (d *dstorage) UpdateKeys(updater func(old storage.Keys) (storage.Keys, error)) (err error) {
	old, err := d.GetKeys()
	if err != nil && err != storage.ErrNotFound {
		return errors.Wrapf(err, "Error updating item %q in namespace %q", keysKey, keysNS)
	}
	keys, err := updater(old)
	if err != nil {
		return errors.Wrap(err, "Error running keys update function")
	}
	kb, err := json.Marshal(&keys)
	if err != nil {
		return errors.Wrap(err, "Error marshaling keys")
	}
	bm := storagepb.Bytes{Data: kb}
	mreq, err := istorage.PutMutation(keysNS, keysKey, &bm, nil)
	if err != nil {
		return errors.Wrap(err, "Error building put mutation")
	}
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrap(err, "Error putting updated keys")
	}
	return nil
}

func (d *dstorage) UpdateAuthRequest(id string, updater func(old storage.AuthRequest) (storage.AuthRequest, error)) (err error) {
	old, err := d.GetAuthRequest(id)
	if err != nil && err != storage.ErrNotFound {
		return errors.Wrapf(err, "Error updating item %q in namespace %q", id, authRequestNS)
	}
	authReq, err := updater(old)
	if err != nil {
		return errors.Wrap(err, "Error running auth request update function")
	}
	ab, err := json.Marshal(&authReq)
	if err != nil {
		return errors.Wrap(err, "Error marshaling auth request")
	}
	bm := storagepb.Bytes{Data: ab}
	mreq, err := istorage.PutMutation(authRequestNS, id, &bm, nil)
	if err != nil {
		return errors.Wrap(err, "Error building put mutation")
	}
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrap(err, "Error putting updated keys")
	}
	return nil
}

func (d *dstorage) UpdatePassword(email string, updater func(p storage.Password) (storage.Password, error)) (err error) {
	panic("not supported")
}

func (d *dstorage) UpdateRefreshToken(id string, updater func(p storage.RefreshToken) (storage.RefreshToken, error)) (err error) {
	old, err := d.GetRefresh(id)
	if err != nil && err != storage.ErrNotFound {
		return errors.Wrapf(err, "Error updating item %q in namespace %q", id, refreshTokenNS)
	}
	rt, err := updater(old)
	if err != nil {
		return errors.Wrap(err, "Error running refresh token update function")
	}
	rb, err := json.Marshal(&rt)
	if err != nil {
		return errors.Wrap(err, "Error marshaling refresh token request")
	}
	bm := storagepb.Bytes{Data: rb}
	mreq, err := istorage.PutMutation(refreshTokenNS, id, &bm, nil)
	if err != nil {
		return errors.Wrap(err, "Error building put mutation")
	}
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrap(err, "Error putting updated keys")
	}
	return nil
}

func (d *dstorage) UpdateOfflineSessions(userID string, connID string, updater func(o storage.OfflineSessions) (storage.OfflineSessions, error)) (err error) {
	old, err := d.GetOfflineSessions(userID, connID)
	if err != nil && err != storage.ErrNotFound {
		return errors.Wrapf(err, "Error updating item %q in namespace %q", connID+"-"+userID, offlineSessionNS)
	}
	os, err := updater(old)
	if err != nil {
		return errors.Wrap(err, "Error running offline session update function")
	}
	ob, err := json.Marshal(&os)
	if err != nil {
		return errors.Wrap(err, "Error marshaling offline session token request")
	}
	bm := storagepb.Bytes{Data: ob}
	mreq, err := istorage.PutMutation(offlineSessionNS, connID+"-"+userID, &bm, nil)
	if err != nil {
		return errors.Wrap(err, "Error building put mutation")
	}
	if _, err := d.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrap(err, "Error putting updated keys")
	}
	return nil

}

func (d *dstorage) UpdateConnector(id string, updater func(c storage.Connector) (storage.Connector, error)) (err error) {
	panic("not supported")
}
