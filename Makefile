commons:
	echo "building binary ..."
	mkdir -p bin
	go mod tidy

linux:	commons
	GOOS=linux CGO_ENABLED=0 go build -ldflags "-w -s" -pgo=default.pgo -o bin/sslsearch_linux .

darwin: commons
	GOOS=darwin CGO_ENABLED=0 go build -ldflags "-w -s" -pgo=default.pgo -o bin/sslsearch_darwin .

race: commons
	GOOS=linux CGO_ENABLED=1 go build -race -ldflags "-w -s" -pgo=default.pgo -o bin/sslsearch_linux .

all: linux darwin
