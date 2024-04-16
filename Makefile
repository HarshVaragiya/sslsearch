build:
	echo "building binary"
	mkdir -p bin
	go build -o bin/sslsearch .
