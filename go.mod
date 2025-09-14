module lds.li/webauthn-oidc-idp

go 1.25

require (
	github.com/alecthomas/kong v1.12.1
	github.com/chromedp/cdproto v0.0.0-20250403032234-65de8f5d025b
	github.com/chromedp/chromedp v0.13.7
	github.com/descope/virtualwebauthn v1.0.3
	github.com/go-webauthn/webauthn v0.13.4
	github.com/google/uuid v1.6.0
	github.com/lstoll/tinkrotate v0.0.0-20250628134202-3c7c777eb215
	github.com/mattn/go-sqlite3 v1.14.32
	github.com/oklog/run v1.2.0
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/common v0.66.1
	github.com/tailscale/hujson v0.0.0-20250605163823-992244df8c5a
	github.com/tink-crypto/tink-go/v2 v2.4.0
	golang.org/x/oauth2 v0.31.0
	golang.org/x/term v0.35.0
	google.golang.org/protobuf v1.36.9
	lds.li/oauth2ext v0.0.0-20250914220420-caee5f388b4a
	lds.li/web v0.0.0-20250914000751-5c4fa2ecb9d7
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.2 // indirect
	github.com/go-json-experiment/json v0.0.0-20250211171154-1ae217ad3535 // indirect
	github.com/go-webauthn/x v0.1.25 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

replace crawshaw.dev/jsonfile => github.com/sr/jsonfile v0.0.0-20240301210704-69e8a5b5b148
