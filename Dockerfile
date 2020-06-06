FROM golang:1.13-alpine AS builder
COPY . /src
WORKDIR /src
RUN go build

FROM alpine:latest
COPY --from=builder /src/dsds /usr/local/bin/dsds

CMD ["/usr/local/bin/dsds"]
