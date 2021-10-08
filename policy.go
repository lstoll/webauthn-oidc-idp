package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/pardot/oidc"
)

// evalClaimsPolicy evaluates the upstream claims against the given policy,
// returning a decision if they user should be granted access or not.
func evalClaimsPolicy(ctx context.Context, policy []byte, query string, claims oidc.Claims) (bool, error) {
	rq, err := rego.New(
		rego.Query(query),
		rego.Module("authz.rego", string(policy)),
	).PrepareForEval(ctx)
	if err != nil {
		return false, fmt.Errorf("preparing policy: %v", err)
	}

	cljson, err := json.Marshal(claims)
	if err != nil {
		return false, fmt.Errorf("marshaling claims: %v", err)
	}

	cldata := map[string]interface{}{}

	if err := json.Unmarshal(cljson, &cldata); err != nil {
		return false, fmt.Errorf("unmarshaling claims: %v", err)
	}

	var (
		result bool
		ok     bool
	)

	results, err := rq.Eval(ctx, rego.EvalInput(claims))
	if err != nil {
		return false, fmt.Errorf("evaluating query: %v", err)
	} else if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, fmt.Errorf("query failed to return results")
	} else if result, ok = results[0].Expressions[0].Value.(bool); !ok {
		return false, fmt.Errorf("query unexpected type return from claims policy: %T", results[0].Expressions[0].Value)
	}

	return result, nil
}
