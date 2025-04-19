FROM golang:1.24-bookworm AS build

WORKDIR /src

COPY go.mod go.sum compilestub.go ./
RUN go mod download && \
    go build -tags compilestub -o /dev/null compilestub.go # pre-compile sqlite3 module

COPY . .

RUN go install -ldflags "\
    -X 'github.com/prometheus/common/version.Branch=$(git describe --contains --all HEAD)' \
    -X 'github.com/prometheus/common/version.BuildUser=$(whoami)' \
    -X 'github.com/prometheus/common/version.BuildDate=$(date --utc --iso-8601=seconds)'" \
    ./...

FROM debian:bookworm

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates sqlite3

COPY --from=build /go/bin/webauthn-oidc-idp /usr/bin/

CMD ["/usr/bin/webauthn-oidc-idp"]
