.PHONY: build
build:
	sam build

.PHONY: lint
lint:
	golangci-lint ./...

# assumes that docker-compose is running
.PHONY: run-local
run-local: build
	sam local start-api --env-vars env.json --docker-network lambdaid

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
	-aws s3 --endpoint-url http://localhost:8028 mb s3://lambdaid
	aws s3 --endpoint-url http://localhost:8028 sync devbucket/ s3://lambdaid/
