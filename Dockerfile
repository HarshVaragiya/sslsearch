FROM golang:buster as builder
WORKDIR /app
COPY . /app/
ENV CGO_ENABLED 0
ENV GOOS linux
RUN make build

FROM alpine
WORKDIR /app
COPY --from=builder /app/bin/sslsearch /app/sslsearch
ENTRYPOINT ["/app/sslsearch"]