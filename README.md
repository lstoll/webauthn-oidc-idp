# idp

**note:** this is very much experimental softawre. it is probably not stable nor secure. don't use it!

See [Issues](/../../issues) for the closest thign we have to a roadmap.

## Run E2E Tests

`TEST_E2E=1 go test ./e2e -count=1`

## Registering an initial user

```
go run ./cmd/webauthn-oidc-idp -selected-issuer=https://localhost:8085 enroll-user -email=<email> -fullname="<name>"
```

## Run the server

One time, need to create certs:

```
brew install mkcert
mkcert -install
mkcert -cert-file=dev-cert.pem -key-file=dev-key.pem localhost
```

```
go run ./cmd/webauthn-oidc-idp --db-path=data/idp.db --issuer=https://locahost:8085 serve --static-clients-file=etc/dev-clients.hujson --cert-file=dev-cert.pem --key-file=dev-key.pem --listen-addr=localhost:8085
# test the auth flow:
go run github.com/lstoll/oauth2ext/cmd/oidc-example-rp@latest
go run github.com/lstoll/oauth2ext/cmd/oidccli@latest -issuer=https://localhost:8085 -client-id=cli info
```
