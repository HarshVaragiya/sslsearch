FROM almalinux:latest as builder
WORKDIR /app
COPY . /app/
ENV CGO_ENABLED 0
ENV GOOS linux
RUN yum install golang-bin make -y && make linux && yum clean all

FROM almalinux:minimal
WORKDIR /app
COPY --from=builder /app/bin/sslsearch_linux /app/sslsearch
ENTRYPOINT ["/app/sslsearch"]
