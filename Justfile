# Justfile for MailWatcher CLI

version := `git describe --tags --always`
ldflags := "-X main.version=v" + version 


build-macos:
	@echo "Building MailWatcher CLI for MacOS..."
	GOOS=darwin go build -ldflags "{{ldflags}}" -o mailwatcher-macos

build-linux-amd64:
	@echo "Building MailWatcher CLI for Linux AMD64..."
	GOOS=linux GOARCH=amd64 go build -ldflags "{{ldflags}}" -o mailwatcher-linux-amd64

build-linux-arm64:
    @echo "Building MailWatcher CLI for Linux ARM64..."
    GOOS=linux GOARCH=arm64 go build -ldflags "{{ldflags}}" -o mailwatcher-linux-arm64

clean:
    rm -f mailwatcher-*

dist:
	just build-macos
	tar -czpf mailwatcher-macos.tar.gz mailwatcher-macos
	aws s3 cp ./mailwatcher-macos.tar.gz $CLOUDFLARE_R2_BUCKET/mailwatcher-macos.tar.gz --endpoint-url $CLOUDFLARE_R2_ENDPOINT

	just build-linux-amd64
	tar -czpf mailwatcher-linux-amd64.tar.gz mailwatcher-linux-amd64
	aws s3 cp ./mailwatcher-linux-amd64.tar.gz $CLOUDFLARE_R2_BUCKET/mailwatcher-linux-amd64.tar.gz --endpoint-url $CLOUDFLARE_R2_ENDPOINT

	just build-linux-arm64
	tar -czpf mailwatcher-linux-arm64.tar.gz mailwatcher-linux-arm64
	aws s3 cp ./mailwatcher-linux-arm64.tar.gz $CLOUDFLARE_R2_BUCKET/mailwatcher-linux-arm64.tar.gz --endpoint-url $CLOUDFLARE_R2_ENDPOINT
	just clean

run *ARGS:
        go run main.go {{ARGS}}

test:
    go test ./...
