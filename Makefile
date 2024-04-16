build:
	echo "building binary"
	mkdir -p bin
	GOOS=linux CGO_ENABLED=0 go build -o bin/sslsearch .
