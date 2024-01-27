package main

import (
	"context"
	"testing"

	"github.com/lstoll/oidc"
)

var policyOK = []byte(`
package upstream

default allow = false

allow = true {
    input.sub == "a@b.com"
}`)

func TestPolicyEnforcement(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		Name    string
		Claims  oidc.Claims
		Allowed bool
	}{
		{
			Name: "Allowed subject",
			Claims: oidc.Claims{
				Subject: "a@b.com",
			},
			Allowed: true,
		},
		{
			Name: "Unallowed subject",
			Claims: oidc.Claims{
				Subject: "c@d.com",
			},
			Allowed: false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ok, err := evalClaimsPolicy(ctx, policyOK, "data.upstream.allow", tc.Claims)
			if err != nil {
				t.Fatalf("evaluation error: %v", err)
			}
			if ok != tc.Allowed {
				t.Errorf("want allowed %t, got %t", tc.Allowed, ok)
			}
		})
	}
}
