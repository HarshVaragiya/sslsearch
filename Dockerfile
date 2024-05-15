FROM almalinux:latest as builder
WORKDIR /app
COPY . /app/
ENV CGO_ENABLED 0
ENV GOOS linux
RUN yum install golang-bin make -y && make build && yum clean all

FROM almalinux:minimal
WORKDIR /app
COPY --from=builder /app/bin/sslsearch /app/sslsearch
ENTRYPOINT ["/app/sslsearch"]
