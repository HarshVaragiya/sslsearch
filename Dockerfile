FROM golang:alpine AS builder
WORKDIR /app
COPY . /app/
RUN apk add make && make linux

FROM alpine
WORKDIR /app
COPY --from=builder /app/bin/sslsearch_linux /app/sslsearch
ENTRYPOINT ["/app/sslsearch"]
