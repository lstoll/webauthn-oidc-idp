.PHONY: build
build:
	sam build

.PHONY: run-local
run-local: build
	sam local start-api --env-vars env.json

.PHONY: run-dynamo
run-dynamo:
	# -v $(shell pwd)/dynamodata:/data enables a state mount, # -dbPath /data on the command
	# skip for now, we don't rely on it's persistence
	# use -sharedDb so any client ID hits the same database, not sure what sam is using
	docker run --rm -p 8027:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -sharedDb -sharedDb

.PHONY: create-dynamo-tables
create-dynamo-tables: export AWS_REGION = us-east-1
create-dynamo-tables: export AWS_ACCESS_KEY_ID = akai
create-dynamo-tables: export AWS_SECRET_ACCESS_KEY = abcdef
create-dynamo-tables:
	aws dynamodb --endpoint-url http://localhost:8027 create-table --billing-mode PAY_PER_REQUEST --table-name sessions --attribute-definitions AttributeName=session_id,AttributeType=S --key-schema AttributeName=session_id,KeyType=HASH
	aws dynamodb --endpoint-url http://localhost:8027 update-time-to-live --table-name sessions --time-to-live-specification "Enabled=true, AttributeName=expires_at"
