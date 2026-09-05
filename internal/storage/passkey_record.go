package storage

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passkeyRecordPrefix = "$webauthn$v=1$"

// EncodePasskeyRecord encodes a registration credential as a C2SP passkey record.
// https://c2sp.org/passkey-record
func EncodePasskeyRecord(cred *webauthn.Credential) (string, error) {
	if cred == nil {
		return "", fmt.Errorf("missing credential")
	}
	raw, err := registrationAuthData(cred)
	if err != nil {
		return "", err
	}
	var authData protocol.AuthenticatorData
	if err := authData.Unmarshal(raw); err != nil {
		return "", fmt.Errorf("parse authenticator data: %w", err)
	}
	if !authData.Flags.HasAttestedCredentialData() {
		return "", fmt.Errorf("authenticator data is not from registration")
	}

	var b strings.Builder
	b.WriteString(passkeyRecordPrefix)
	if param, ok := transportsParam(cred.Transport); ok {
		b.WriteString("transports=")
		b.WriteString(param)
		b.WriteByte('$')
	}
	b.WriteString(base64.RawStdEncoding.EncodeToString(raw))
	return b.String(), nil
}

// CredentialFromPasskeyRecord decodes a C2SP passkey record into the
// go-webauthn credential fields needed for assertion verification.
func CredentialFromPasskeyRecord(record string) (*webauthn.Credential, error) {
	raw, transports, err := parsePasskeyRecord(record)
	if err != nil {
		return nil, err
	}
	var authData protocol.AuthenticatorData
	if err := authData.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf("parse authenticator data: %w", err)
	}
	if !authData.Flags.HasAttestedCredentialData() {
		return nil, fmt.Errorf("authenticator data is not from registration")
	}
	return &webauthn.Credential{
		ID:        authData.AttData.CredentialID,
		PublicKey: authData.AttData.CredentialPublicKey,
		Transport: transports,
		Flags:     webauthn.NewCredentialFlags(authData.Flags),
		Authenticator: webauthn.Authenticator{
			AAGUID:    authData.AttData.AAGUID,
			SignCount: authData.Counter,
		},
	}, nil
}

func parsePasskeyRecord(record string) ([]byte, []protocol.AuthenticatorTransport, error) {
	if !strings.HasPrefix(record, "$webauthn$") {
		return nil, nil, fmt.Errorf("not a passkey record")
	}
	parts := strings.Split(record, "$")
	// "", "webauthn", params..., payload
	if len(parts) < 4 || parts[1] != "webauthn" {
		return nil, nil, fmt.Errorf("invalid passkey record")
	}
	payload := parts[len(parts)-1]
	if payload == "" {
		return nil, nil, fmt.Errorf("passkey record missing authenticator data")
	}
	var versionOK bool
	var transports []protocol.AuthenticatorTransport
	for _, part := range parts[2 : len(parts)-1] {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, nil, fmt.Errorf("invalid passkey record parameter %q", part)
		}
		switch key {
		case "v":
			if value != "1" {
				return nil, nil, fmt.Errorf("unsupported passkey record version %q", value)
			}
			versionOK = true
		case "transports":
			if value == "" {
				return nil, nil, fmt.Errorf("empty transports parameter")
			}
			seen := make(map[string]struct{})
			names := strings.Split(value, "+")
			if !slices.IsSorted(names) {
				return nil, nil, fmt.Errorf("transports are not sorted")
			}
			for _, name := range names {
				if _, dup := seen[name]; dup {
					return nil, nil, fmt.Errorf("duplicate transport %q", name)
				}
				seen[name] = struct{}{}
				transports = append(transports, protocol.AuthenticatorTransport(name))
			}
		}
	}
	if !versionOK {
		return nil, nil, fmt.Errorf("passkey record missing version")
	}
	raw, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("decode authenticator data: %w", err)
	}
	return raw, transports, nil
}

func registrationAuthData(cred *webauthn.Credential) ([]byte, error) {
	if len(cred.Attestation.AuthenticatorData) > 0 {
		return cred.Attestation.AuthenticatorData, nil
	}
	if len(cred.Attestation.Object) == 0 {
		return nil, fmt.Errorf("credential is missing registration authenticator data")
	}
	var obj struct {
		AuthData []byte `json:"authData"`
	}
	if err := webauthncbor.Unmarshal(cred.Attestation.Object, &obj); err != nil {
		return nil, fmt.Errorf("parse attestation object: %w", err)
	}
	if len(obj.AuthData) == 0 {
		return nil, fmt.Errorf("attestation object is missing authenticator data")
	}
	return obj.AuthData, nil
}

func transportsParam(transports []protocol.AuthenticatorTransport) (string, bool) {
	names := make([]string, 0, len(transports))
	seen := make(map[string]struct{}, len(transports))
	for _, transport := range transports {
		name := string(transport)
		if name == "" || !transportNameOK(name) {
			return "", false
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		return "", false
	}
	slices.Sort(names)
	return strings.Join(names, "+"), true
}

func transportNameOK(name string) bool {
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}
