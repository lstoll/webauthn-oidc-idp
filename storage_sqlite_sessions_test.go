package main

import (
	"context"
	"testing"
	"time"
)

func TestSessionID(t *testing.T) {
	id := mustNewSessionID()
	t.Logf("got id: %s", id)
}

func TestWebSessions(t *testing.T) {
	ctx := context.Background()
	st := newTestStorage(t)

	_, ok, err := st.GetWebSession(ctx, "aaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("should not get empty session")
	}

	ws, err := st.CreateWebSession(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := st.PutWebSession(ctx, ws, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	ws, ok, err = st.GetWebSession(ctx, ws.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("should have got session")
	}

	if err := st.DeleteWebSession(ctx, ws.SessionID); err != nil {
		t.Fatal(err)
	}
}
