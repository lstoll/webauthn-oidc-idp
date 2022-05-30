FROM golang:1.18-bullseye AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go install ./...

FROM debian:bullseye

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY --from=build /go/bin/idp /usr/bin/

CMD ["/usr/bin/idp"]
