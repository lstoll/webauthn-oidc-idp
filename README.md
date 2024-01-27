# idp

**note:** this is very much experimental softawre. it is probably not stable nor secure. don't use it!

See [Issues](/../../issues) for the closest thign we have to a roadmap.

## Registering an initial user

```
PASSPHRASE="$(openssl rand -hex 32)"
go run ./ --enroll --email=user@domain --fullname="Users Name" --secure-passphrase "${PASSPHRASE}"
# go to the url output
go run ./ --activate --user-id=<uuid> --secure-passphrase "${PASSPHRASE}"
```

## Run the server

```
go run ./ --issuer http://localhost:8085 --http 127.0.0.1:8085 --secure-passphrase "${PASSPHRASE}"
# test the auth flow:
go run github.com/lstoll/oidc/cmd/oidc-example-rp@latest
```
