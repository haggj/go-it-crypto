## Running tests

```bash
CGO_ENABLED=0 GODEBUG=x509sha1=1 go test -v ./...
```

## Update go package

1. Commit changes
2. Tag new version: `git tag v1.2.3`
3. Push version `git push origin v.1.2.3`
4. Push version to package index `GOPROXY=proxy.golang.org go list -m github.com/haggj/go-it-crypto@v1.2.3`