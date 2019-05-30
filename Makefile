BINARY := suricata-rule-generator

VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || (git describe --always --long --dirty|tr '\n' '-';date +%Y.%m.%d))
LDFLAGS = -ldflags "-w -s -X main.version=${VERSION}"
LDFLAGS_DEV = -ldflags "-X main.version=${VERSION}"

#Build release builds
release: 
	@CGO_ENABLED=0 gox -osarch="darwin/386 darwin/amd64 linux/386 linux/amd64 windows/386 windows/amd64" ${LDFLAGS} -output="bin/{{.Dir}}_{{.OS}}_{{.Arch}}"

#Build a development build
dev: 
	@CGO_ENABLED=0 go build --installsuffix cgo ${LDFLAGS_DEV} -o bin/${BINARY}

#Install a release build on your local system
install: clean
	@go install ${LDFLAGS}

clean: 
	@go clean -i
