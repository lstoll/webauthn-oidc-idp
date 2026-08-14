package storage_test

import (
	"testing"

	"lds.li/passidp/internal/storage"
)

func TestStateSQLitePath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "data/state.bolt", want: "data/state.sqlite"},
		{in: "/data/state.bolt", want: "/data/state.sqlite"},
		{in: "data/state.sqlite", want: "data/state.sqlite"},
		{in: "data/state", want: "data/state.sqlite"},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			if got := storage.StateSQLitePath(test.in); got != test.want {
				t.Fatalf("StateSQLitePath(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}
