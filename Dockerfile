FROM golang:1.24-bookworm AS build

WORKDIR /src

COPY go.mod go.sum compilestub.go ./
RUN go mod download && \
    go build -tags compilestub -o /dev/null compilestub.go # pre-compile sqlite3 module

COPY . .

RUN go install ./cmd/webauthn-oidc-idp

FROM debian:bookworm

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates sqlite3 procps

COPY --from=build /go/bin/webauthn-oidc-idp /usr/bin/

CMD ["/usr/bin/webauthn-oidc-idp"]
