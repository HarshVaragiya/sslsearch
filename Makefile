commons:
	echo "building binary ..."
	mkdir -p bin
	go mod tidy

linux:	commons
	GOOS=linux CGO_ENABLED=0 go build -pgo=default.pgo -o bin/sslsearch_linux .

darwin: commons
	GOOS=darwin CGO_ENABLED=0 go build -pgo=default.pgo -o bin/sslsearch_darwin .

all: linux darwin
