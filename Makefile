commons:
	echo "building binary ..."
	mkdir -p bin

linux:	commons
	GOOS=linux CGO_ENABLED=0 go build -o bin/sslsearch_linux .

darwin: commons
	GOOS=darwin CGO_ENABLED=0 go build -o bin/sslsearch_darwin .