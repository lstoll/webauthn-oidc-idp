.PHONY: build
build:
	sam build

.PHONY: run-local
run-local: build
	sam local start-api --env-vars env.json
