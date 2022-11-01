## Running tests

```bash
CGO_ENABLED=0 GODEBUG=x509sha1=1 go test -v ./...
```