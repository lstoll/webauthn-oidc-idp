package oidc

import (
	"encoding/json"
	"log"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/lstoll/idp"
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
	Storage      idp.Storage
	clientLookup func(clientID string) (client *idppb.OIDCClient, ok bool, err error)
}

func (d *dstorage) Close() error { return nil }

func (d *dstorage) GarbageCollect(now time.Time) (result storage.GCResult, err error) {
	// TODO - implement
	return result, nil
}

func (d *dstorage) createInIS(namespace, itemID string, item interface{}) error {
	_, err := d.Storage.Get(namespace, itemID)
	if err == nil { // got the item successfully, dupe!
		return storage.ErrAlreadyExists
	} else if err != nil && !d.Storage.ErrIsNotFound(err) { // we have an actual error
		return errors.Wrapf(err, "Error checking for existence of item %q in namespace %q", itemID, namespace)
	}
	ib, err := json.Marshal(item)
	if err != nil {
		return errors.Wrapf(err, "Error marshaling item %q in namespace %q", itemID, namespace)
	}
	if err := d.Storage.Put(namespace, itemID, ib); err != nil {
		return errors.Wrapf(err, "Error storing item %q in namespace %q", itemID, namespace)

	}
	return nil
}

func (d *dstorage) getFromNS(namespace, itemID string, into interface{}) error {
	ib, err := d.Storage.Get(namespace, itemID)
	if err != nil {
		if d.Storage.ErrIsNotFound(err) {
			return storage.ErrNotFound
		}
		return errors.Wrapf(err, "Error getting item %q from namespace %q", itemID, namespace)
	}
	if err := json.Unmarshal(ib, into); err != nil {
		return errors.Wrapf(err, "Error unmarshaling item %q from namespace %q", itemID, namespace)
	}
	return nil
}

func (d *dstorage) CreateClient(c storage.Client) error {
	panic("not supported")
}

func (d *dstorage) CreateAuthCode(a storage.AuthCode) (err error) {
	return d.createInIS(authCodeNS, a.ID, &a)
}

func (d *dstorage) CreateRefresh(r storage.RefreshToken) (err error) {
	return d.createInIS(refreshTokenNS, r.ID, &r)
}

func (d *dstorage) CreateAuthRequest(a storage.AuthRequest) (err error) {
	return d.createInIS(authRequestNS, a.ID, &a)
}

func (d *dstorage) CreatePassword(p storage.Password) (err error) {
	panic("not supported")
}

func (d *dstorage) CreateOfflineSessions(o storage.OfflineSessions) (err error) {
	return d.createInIS(authRequestNS, o.ConnID+"-"+o.UserID, &o)
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
	var innerErr error
	err = d.Storage.List(refreshTokenNS, func(items map[string][]byte) bool {
		for _, v := range items {
			rt := storage.RefreshToken{}
			if err := json.Unmarshal(v, &rt); err != nil {
				innerErr = errors.Wrap(err, "Error unmarshing")
				return false
			}
			tokens = append(tokens, rt)
		}
		return true
	})
	if innerErr != nil {
		return nil, innerErr
	}
	return tokens, err
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
	if err := d.Storage.Delete(refreshTokenNS, id); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", id, refreshTokenNS)
	}
	return nil
}

func (d *dstorage) DeleteAuthCode(id string) (err error) {
	if err := d.Storage.Delete(authCodeNS, id); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", id, refreshTokenNS)
	}
	return nil
}

func (d *dstorage) DeleteAuthRequest(id string) (err error) {
	if err := d.Storage.Delete(authRequestNS, id); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", id, refreshTokenNS)
	}
	return nil
}

func (d *dstorage) DeleteOfflineSessions(userID string, connID string) (err error) {
	if err := d.Storage.Delete(offlineSessionNS, connID+"-"+userID); err != nil {
		return errors.Wrapf(err, "Error deleting item %q from namespace %q", connID+"-"+userID, refreshTokenNS)
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
	if err := d.Storage.Put(keysNS, keysKey, kb); err != nil {
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
	if err := d.Storage.Put(authRequestNS, id, ab); err != nil {
		return errors.Wrap(err, "Error putting updated auth request")
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
	if err := d.Storage.Put(refreshTokenNS, id, rb); err != nil {
		return errors.Wrap(err, "Error putting updated refresh token request")
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
	if err := d.Storage.Put(offlineSessionNS, connID+"-"+userID, ob); err != nil {
		return errors.Wrap(err, "Error putting updated offline session token request")
	}
	return nil

}

func (d *dstorage) UpdateConnector(id string, updater func(c storage.Connector) (storage.Connector, error)) (err error) {
	panic("not supported")
}
