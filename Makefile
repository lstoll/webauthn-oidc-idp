GOPATH = $(shell go env GOPATH)

all: $(GOPATH)/bin/idp

.PHONY: $(GOPATH)/bin/idp
$(GOPATH)/bin/idp:
	go install .

.PHONY: lint
lint:
	golangci-lint run ./...

# assumes that docker-compose is running
.PHONY: run-local
run-lambda-local: export AWS_REGION = us-east-1
run-lambda-local: export AWS_ACCESS_KEY_ID = defaultkey
run-lambda-local: export AWS_SECRET_ACCESS_KEY = defaultsecret
run-lambda-local: export S3_CONFIG_ENDPOINT = http://localhost:8028
run-lambda-local: export S3_FORCE_CONFIG_PATH_STYLE = true
run-lambda-local: $(GOPATH)/bin/idp miniosync
	$(GOPATH)/bin/idp

.PHONY: create-dynamo-tables
create-dynamo-tables: export AWS_REGION = us-east-1
create-dynamo-tables: export AWS_ACCESS_KEY_ID = defaultkey
create-dynamo-tables: export AWS_SECRET_ACCESS_KEY = defaultsecret
create-dynamo-tables:
	aws dynamodb --endpoint-url http://localhost:8027 create-table --billing-mode PAY_PER_REQUEST --table-name sessions --attribute-definitions AttributeName=session_id,AttributeType=S --key-schema AttributeName=session_id,KeyType=HASH
	aws dynamodb --endpoint-url http://localhost:8027 update-time-to-live --table-name sessions --time-to-live-specification "Enabled=true, AttributeName=expires_at"

.PHONY: miniosync
miniosync: export AWS_REGION = us-east-1
miniosync: export AWS_ACCESS_KEY_ID = defaultkey
miniosync: export AWS_SECRET_ACCESS_KEY = defaultsecret
miniosync:
	-aws s3 --endpoint-url http://localhost:8028 mb s3://idp
	aws s3 --endpoint-url http://localhost:8028 sync config/dev-lambda/ s3://idp/config/

.PHONY: test-integration-local
test-integration-local: export AWS_REGION = us-east-1
test-integration-local: export AWS_ACCESS_KEY_ID = defaultkey
test-integration-local: export AWS_SECRET_ACCESS_KEY = defaultsecret
test-integration-local: export MINIO_URL = http://localhost:8028
test-integration-local:
	go test .
