# Lambda ID

Example OIDC IDP that runs in lambda, using various AWS services.

## Running locally

Boot up dynnamo/mini with `docker-compose up`

Create the dynamo tables `make create-dynamo-tables`

Sync data into minio `miniosync`

Boot up the server `make run-local`. Code changes can be hot deployed to this with `make build`

It can be tested against the [oidc-example-rp](https://github.com/pardot/oidc/tree/ffcb728ee49b67764cb78e993f28f26e8b58e9d4/cmd/oidc-example-rp) `oidc-example-rp -issuer=http://localhost:3000`

## Deploying

Use the sam cli. Update samconfig.toml with stack params:

`parameter_overrides = "DomainName=\"XX.XX.XXX\" HostedZoneID=\"Z03959043OXXXXX\" CertificateARN=\"arn:aws:acm:us-east-1:04XXXXX:certificate/XXXXX\" OIDCSignerKeyARN=\"arn:aws:kms:us-east-1:XXXXX:key/XXXXX\" GoogleOIDCClientID=\"XXXX-XXXXXX\" GoogleOIDCClientSecret=\"XXXXX\""`

Build and deploy `sam build && aws-vault exec XX -- sam deploy`

Check logs `aws-vault exec XX -- sam logs --stack-name XX -n IDPFunction --region us-east-1`
