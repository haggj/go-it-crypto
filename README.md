# Go-It-Crypto

This go module implements E2EE encryption functionality for the inverse transparency toolchain [[1]](#1).
It was developed in the scope of my [master thesis at TUM](https://github.com/haggj/Masterarbeit). 
It is fully compatible with the corresponding Typescript library [ts-it-crypto](https://github.com/haggj/ts-it-crypto) and Python library [py-it-crypto](https://github.com/haggj/py-it-crypto).
The module was published to the [go package index](https://pkg.go.dev/github.com/haggj/go-it-crypto).

For a detailed description of the implemented protocol, security considerations and software architecture have a look to the thesis.

## Installation
To use the go-it-crypto module you can install it with:
`go install github.com/haggj/go-it-crypto`
or
`go get github.com/haggj/go-it-crypto`

## Usage

The functionality of this library requires a function that resolves the identity of users to a `RemoteUser` object.
This objects holds the public keys of a user.
This function is mandatory for decryption since it dynamically resolves the identities to the cryptographic keys
of a user.
This function needs to implement the following signature:
`RemoteUser fetchUser(string)`

Assuming `PubA` and `PrivA` are PEM-encoded public/private keys of a user, the following code
initializes the it-crypto library for the owner of this keypair.

 ```
itCrypto := itcrypto.ItCrypto{FetchUser: fetchUser}
itCrypto.Login(owner.Id, PubA, PubA, PrivA, PrivA)
 ```
The logged-in user can sign AccessLogs:

 ```
signedLog, err := itCrypto.SignAccessLog(accessLog)
 ```

The logged-in user can encrypt SignedAccessLogs for other users:

 ```
cipher, err := itCrypto.Encrypt(signedLog, []user.RemoteUser{receiver1, receiver2})
 ```

The logged-in user can decrypt tokens (this only succeeds if this user was specified as receiver during encryption):

 ```
receivedSignedLog, err := itCrypto.Decrypt(cipher)
receivedAccessLog, err := receivedSignedLog.Extract()
 ```

# Development

## Running tests

```bash
CGO_ENABLED=0 GODEBUG=x509sha1=1 go test -v ./...
```

## Update go package

1. Commit changes
2. Tag new version: `git tag v1.2.3`
3. Push version `git push origin v.1.2.3`
4. Push version to package index `GOPROXY=proxy.golang.org go list -m github.com/haggj/go-it-crypto@v1.2.3`

# References
<a id="1">[1]</a>
Zieglmeier, Valentin and Pretschner, Alexander (2021).
Trustworthy transparency by design (2021).
https://arxiv.org/pdf/2103.10769.pdf