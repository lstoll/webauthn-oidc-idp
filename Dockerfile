FROM golang:1.22-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go install ./...

FROM debian:bookworm

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates sqlite3

COPY --from=build /go/bin/webauthn-oidc-idp /usr/bin/

CMD ["/usr/bin/webauthn-oidc-idp"]
