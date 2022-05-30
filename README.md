# idp

**note:** this is very much experimental softawre. it is probably not stable nor secure. don't use it!

See [Issues](/../../issues) for the closest thign we have to a roadmap.

## Registering an initial user

```
go install . && webauthn-oidc-idp adduser --user-id=username --email=user@domain --fullname="Users Name"
# go to the url output
go install . && webauthn-oidc-idp activate-user --user-id=username
```
