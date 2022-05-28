package main

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type testRotatable struct {
	ObjID string       `json:"id"`
	Stage rotatorStage `json:"rotator_stage"`
}

// ID returns the globally unique ID for this item
func (t *testRotatable) ID() string {
	return t.ObjID
}

// Initialize is called when a new rotatable is created. This can be used to
// set up the object
func (t *testRotatable) Initialize() error {
	if t.ObjID == "" {
		t.ObjID = uuid.NewString()
	}
	return nil
}

// Rotate is called on each rotation, with the stage the key is being
// rotated in to.
// TODO - call consistently, not called for previous
func (t *testRotatable) Rotate(stage rotatorStage) error {
	t.Stage = stage
	return nil
}

func TestSSHSigner(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	const testUsage = "test"

	dbr := &dbRotator[testRotatable, *testRotatable]{
		db:  s.db,
		log: logrus.New(),

		usage: "test",

		rotateInterval: 1 * time.Minute,
		maxAge:         10 * time.Minute,
	}

	if _, err := dbr.GetCurrent(ctx); err == nil {
		t.Error("should have got an error gteting the signer key on an uninitialized DB")
	}

	// t.Run(tc.Name, func(t *testing.T) {
	defer logTable(t, s.db, "rotatable")

	if err := dbr.RotateIfNeeded(ctx); err != nil {
		t.Fatalf("want no error rotating, got: %v", err)
	}

	ck, err := dbr.GetCurrent(ctx)
	if err != nil {
		t.Fatalf("unexpected err getting signing key: %v", err)
	}

	for i := 0; i < 10; i++ {
		if err := dbr.RotateIfNeeded(ctx); err != nil {
			t.Fatalf("want no error rotating, got: %v", err)
		}
	}

	ck2, err := dbr.GetCurrent(ctx)
	if err != nil {
		t.Fatalf("unexpected err getting signing key: %v", err)
	}

	if ck2.ObjID != ck.ObjID {
		t.Errorf("want current key to not change on immediate rotate, but it did")
	}

	logTable(t, s.db, "rotatable")
	dbShift(t, ctx, dbr.db, -2*time.Minute)
	logTable(t, s.db, "rotatable")

	for i := 0; i < 10; i++ {
		if err := dbr.RotateIfNeeded(ctx); err != nil {
			t.Fatalf("want no error rotating, got: %v", err)
		}
	}

	ck3, err := dbr.GetCurrent(ctx)
	if err != nil {
		t.Fatalf("unexpected err getting signing key: %v", err)
	}

	if ck3.ObjID == ck.ObjID {
		t.Errorf("id %s should have rotated out, but got %s", ck.ObjID, ck3.ObjID)
	}
}

func dbShift(t *testing.T, ctx context.Context, db *sql.DB, amount time.Duration) {
	t.Helper()

	// shift everything back 2 minutes, should cause a rotation
	for _, col := range []string{"created_at", "current_at", "previous_at", "expires_at"} {
		q := fmt.Sprintf("update rotatable set %s=datetime(%s, '%d seconds') where %s is not null", col, col, int(amount.Seconds()), col)
		t.Logf("shift query: %s", q)
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
}
