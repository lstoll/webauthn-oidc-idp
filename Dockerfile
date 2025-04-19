FROM golang:1.24-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /go/bin/webauthn-oidc-idp -ldflags "\
    -X 'github.com/prometheus/common/version.Branch=$(git describe --contains --all HEAD)' \
    -X 'github.com/prometheus/common/version.BuildUser=$(whoami)' \
    -X 'github.com/prometheus/common/version.BuildDate=$(date --utc --iso-8601=seconds)'" \
    ./...

FROM debian:bookworm

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY --from=build /go/bin/webauthn-oidc-idp /usr/bin/

CMD ["/usr/bin/webauthn-oidc-idp"]
