module github.com/lstoll/webauthn-oidc-idp

go 1.24.0

require (
	crawshaw.dev/jsonfile v0.0.0-20240206193014-699d1dad804e
	github.com/chromedp/cdproto v0.0.0-20250403032234-65de8f5d025b
	github.com/chromedp/chromedp v0.13.7
	github.com/go-webauthn/webauthn v0.13.0
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/lstoll/oidc v1.0.0-alpha.1.0.20240324163255-989e22bde1f1
	github.com/lstoll/tinkrotate v0.0.0-20250628134202-3c7c777eb215
	github.com/lstoll/web v0.0.0-20250626220328-c73bfcffd053
	github.com/mattn/go-sqlite3 v1.14.28
	github.com/oklog/run v1.1.0
	github.com/prometheus/client_golang v1.22.0
	github.com/prometheus/common v0.62.0
	github.com/tailscale/hujson v0.0.0-20250605163823-992244df8c5a
	github.com/tink-crypto/tink-go/v2 v2.4.0
	golang.org/x/oauth2 v0.24.0
	golang.org/x/sys v0.33.0
	google.golang.org/protobuf v1.36.6
)

require (
	filippo.io/csrf v0.0.0-20250517103426-cfb6fbb0fbe3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.8.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20250211171154-1ae217ad3535 // indirect
	github.com/go-webauthn/x v0.1.21 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.39.0 // indirect
)

replace crawshaw.dev/jsonfile => github.com/sr/jsonfile v0.0.0-20240301210704-69e8a5b5b148
