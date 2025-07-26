# idp

**note:** this is very much experimental softawre. it is probably not stable nor secure. don't use it!

See [Issues](/../../issues) for the closest thign we have to a roadmap.

## Run E2E Tests

`TEST_E2E=1 go test ./e2e -count=1`

## Registering an initial user

```
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
go run ./ --enroll --email=user@domain --fullname="Users Name"
# go to the url output
go run ./ --activate --user-id=<uuid>
```

## Run the server

One time, need to create certs:

```
brew install mkcert
mkcert -install
mkcert -cert-file=dev-cert.pem -key-file=dev-key.pem localhost
```

```
go run ./cmd/webauthn-oidc-idp serve -cert-file=dev-cert.pem -key-file=dev-key.pem
# test the auth flow:
go run github.com/lstoll/oidc/cmd/oidc-example-rp@latest
```
