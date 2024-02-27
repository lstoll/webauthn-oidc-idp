package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lstoll/oidc/core"
)

func TestOIDCSigner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openTestDB(t)
	os := db.Signer()

	signed, err := os.Sign(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	payload, err := os.VerifySignature(ctx, string(signed))
	if err != nil {
		t.Fatalf("failed to verify JWT: %v", err)
	}

	if !bytes.Equal(payload, []byte("hello")) {
		t.Errorf("payload mismatch")
	}
}

func TestOIDCKeySource(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	keyset, err := db.KeySource().PublicKeys(context.Background())
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	if want, got := 1, len(keyset.Keys); got != want {
		t.Fatalf("want %d public keys, got: %d", want, got)
	}
}

// versionedSession is a core.Session used for testing our SessionManager
// implementation. Adapted from github.com/lstoll/oidc/core.
type versionedSession struct {
	Version string          `json:"version"`
	Session json.RawMessage `json:"session"`
	sess    *sessionV2
}

func (v *versionedSession) ID() string {
	return v.sess.ID
}

func (v *versionedSession) Expiry() time.Time {
	return v.sess.Expiry
}

type sessionV2 struct {
	ID     string    `json:"id,omitempty"`
	Expiry time.Time `json:"expiry,omitempty"`
}

func TestOIDCSessionManager(t *testing.T) {
	t.Parallel()

	sm := openTestDB(t).SessionManager()

	var vsess versionedSession
	ok, err := sm.GetSession(context.Background(), "ID", &vsess)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if ok {
		t.Fatal("GetSession: want session not found, got ok")
	}

	exp := time.Now()

	makeSession := func(version, id string, expiry time.Time) core.Session {
		sess := &sessionV2{ID: id, Expiry: expiry}
		msg, err := json.Marshal(sess)
		if err != nil {
			t.Fatal(err)
		}
		return &versionedSession{
			Version: version,
			Session: msg,
			sess:    sess,
		}
	}

	err = sm.PutSession(context.Background(), makeSession("1", "session-1", exp))
	if err != nil {
		t.Fatalf("PutSession: %v", err)
	}

	ok, err = sm.GetSession(context.Background(), "session-1", &vsess)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !ok {
		t.Fatal("GetSession: want ok to be true, got false")
	}
	if vsess.Version != "1" {
		t.Fatalf("GetSession: want Version 1, got: %s", vsess.Version)
	}
	var sess sessionV2
	if err := json.Unmarshal(vsess.Session, &sess); err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	var v core.Session = &versionedSession{sess: &sess}
	if want, got := "session-1", v.ID(); got != want {
		t.Fatalf("GetSession: want ID() %s, got: %s", want, got)
	}
	if !v.Expiry().Equal(exp) {
		t.Fatalf("GetSession: want Expiry() %s, got: %s", exp, v.Expiry())
	}

	err = sm.PutSession(context.Background(), makeSession("1", "session-1", exp.Add(time.Minute)))
	if err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	ok, err = sm.GetSession(context.Background(), "session-1", &vsess)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !ok {
		t.Fatal("GetSession: want ok to be true, got false")
	}
	if err := json.Unmarshal(vsess.Session, &sess); err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !v.Expiry().Equal(exp.Add(time.Minute)) {
		t.Fatalf("Expiry() not updated after PutSession")
	}

	err = sm.DeleteSession(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	ok, err = sm.GetSession(context.Background(), "session-1", &vsess)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if ok {
		t.Fatal("GetSession returned ok after DeleteSession")
	}
}
