package main

import (
	"testing"
)

func TestOIDCKeyset(t *testing.T) {
	db := openTestDB(t)

	ksm, err := NewKeysetManager(db)
	if err != nil {
		t.Fatal(err)
	}

	for _, ks := range allKeysets {
		if err := ksm.doRotate(ks); err != nil {
			t.Fatal(err)
		}
	}
}
