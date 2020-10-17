# Lambda ID

Example OIDC IDP that runs in lambda, using various AWS services.

# Running locally

Boot up dynnamo/mini with `docker-compose up`

Create the dynamo tables `make create-dynamo-tables`

Sync data into minio `miniosync`

Boot up the server `make run-local`. Code changes can be hot deployed to this with `make build`

It can be tested against the [oidc-example-rp](https://github.com/pardot/oidc/tree/ffcb728ee49b67764cb78e993f28f26e8b58e9d4/cmd/oidc-example-rp) `oidc-example-rp -issuer=http://localhost:3000`
