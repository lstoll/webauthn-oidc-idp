package main

import (
	"testing"
)

func TestOIDCKeyset(t *testing.T) {
	db := openTestDB(t)

	ksm, err := NewOIDCKeysetManager(db)
	if err != nil {
		t.Fatal(err)
	}

	if err := ksm.doRotate(); err != nil {
		t.Fatal(err)
	}
}
