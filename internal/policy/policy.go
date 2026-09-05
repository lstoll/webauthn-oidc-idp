package policy

import (
	"fmt"
	"maps"
	"reflect"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"lds.li/passidp/internal/config"
)

type PolicyEvaluator struct {
	env      *cel.Env
	programs sync.Map // map[string]cel.Program
}

func NewPolicyEvaluator() (*PolicyEvaluator, error) {
	claimsType := cel.MapType(cel.StringType, cel.DynType)

	var env *cel.Env
	var err error
	env, err = cel.NewEnv(
		cel.StdLib(),
		cel.Variable("claims", claimsType),
		cel.Variable("user", cel.MapType(cel.StringType, cel.DynType)),
		cel.Function("patch",
			cel.MemberOverload("claims_patch_map",
				[]*cel.Type{claimsType, cel.MapType(cel.StringType, cel.DynType)},
				claimsType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					return patchClaimsMap(env.CELTypeAdapter(), lhs, rhs)
				}),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("new cel env: %w", err)
	}
	return &PolicyEvaluator{env: env}, nil
}

func (pe *PolicyEvaluator) getProgram(expression string) (cel.Program, error) {
	if val, ok := pe.programs.Load(expression); ok {
		return val.(cel.Program), nil
	}

	ast, issues := pe.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile: %w", issues.Err())
	}

	prg, err := pe.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("program: %w", err)
	}

	pe.programs.Store(expression, prg)
	return prg, nil
}

func (pe *PolicyEvaluator) EvaluateAuthorization(expression string, user *config.User) (bool, error) {
	if expression == "" {
		return true, nil
	}

	prg, err := pe.getProgram(expression)
	if err != nil {
		return false, err
	}

	out, _, err := prg.Eval(map[string]any{
		// TODO - we should expand this with more context, like the dpop/mtls
		// status, more scopes stuff etc.
		"user": celUser(user),
	})
	if err != nil {
		return false, fmt.Errorf("eval: %w", err)
	}

	val, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return a boolean, got %T", out.Value())
	}

	return val, nil
}

func (pe *PolicyEvaluator) EvaluateClaims(expression string, initialClaims map[string]any, user *config.User) (map[string]any, error) {
	if expression == "" {
		return initialClaims, nil
	}

	prg, err := pe.getProgram(expression)
	if err != nil {
		return nil, err
	}

	out, _, err := prg.Eval(map[string]any{
		"claims": initialClaims,
		"user":   celUser(user),
	})
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}

	if out.Type() == types.NullType {
		return initialClaims, nil
	}

	native, err := out.ConvertToNative(reflect.TypeFor[map[string]any]())
	if err != nil {
		return nil, fmt.Errorf("expression did not return a claims map, returned %T: %w", out.Value(), err)
	}
	idClaims, ok := native.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expression did not return a claims map, returned %T", native)
	}
	return idClaims, nil
}

func (pe *PolicyEvaluator) Validate(expression string) error {
	if expression == "" {
		return nil
	}
	_, err := pe.getProgram(expression)
	return err
}

func ValidatePolicies(cfg *config.Config) error {
	pe, err := NewPolicyEvaluator()
	if err != nil {
		return fmt.Errorf("creating policy evaluator: %w", err)
	}

	for _, cl := range cfg.Clients {
		if err := pe.Validate(cl.ClaimsPolicy); err != nil {
			return fmt.Errorf("client %s claims policy: %w", cl.ID, err)
		}
		if err := pe.Validate(cl.AuthorizationPolicy); err != nil {
			return fmt.Errorf("client %s authorization policy: %w", cl.ID, err)
		}
	}
	return nil
}

func celUser(user *config.User) map[string]any {
	return map[string]any{
		"id":       user.ID.String(),
		"email":    user.Email,
		"fullName": user.FullName,
		"groups":   user.Groups,
		"metadata": user.Metadata,
	}
}

func patchClaimsMap(adapter types.Adapter, lhs, rhs ref.Val) ref.Val {
	baseNative, err := lhs.ConvertToNative(reflect.TypeFor[map[string]any]())
	if err != nil {
		return types.NewErr("lhs is not a claims map: %v", err)
	}
	ret := maps.Clone(baseNative.(map[string]any))
	if ret == nil {
		ret = map[string]any{}
	}

	overlay, ok := rhs.(traits.Mapper)
	if !ok {
		return types.NewErr("rhs is not a map, got %T", rhs)
	}
	it := overlay.Iterator()
	for it.HasNext() == types.True {
		key := it.Next()
		k, err := key.ConvertToNative(reflect.TypeFor[string]())
		if err != nil {
			return types.NewErr("patch key is not a string: %v", err)
		}
		val := overlay.Get(key)
		if val.Type() == types.NullType {
			delete(ret, k.(string))
			continue
		}
		native, err := val.ConvertToNative(reflect.TypeFor[any]())
		if err != nil {
			return types.NewErr("patch value conversion: %v", err)
		}
		ret[k.(string)] = native
	}
	return adapter.NativeToValue(ret)
}
