# Go-It-Crypto

This go module implements end-to-end encryption (E2EE) functionality for the inverse transparency toolchain [[1]](#1).
It was developed in the scope of my [master thesis at TUM](https://github.com/haggj/Masterarbeit). 
It is fully compatible with the corresponding Typescript library [ts-it-crypto](https://github.com/haggj/ts-it-crypto) and Python library [py-it-crypto](https://github.com/haggj/py-it-crypto).
The module was published to the [go package index](https://pkg.go.dev/github.com/haggj/go-it-crypto).

For a detailed description of the implemented protocol, security considerations and software architecture have a look to the thesis.

## Installation
To use the go-it-crypto module you can install it with:

`go install github.com/haggj/go-it-crypto` or

`go get github.com/haggj/go-it-crypto`

## Usage

The functionality of this library requires a function that resolves the identity of users to a `RemoteUser` object.
This objects holds the public keys of a user.
This function is mandatory for decryption since it dynamically resolves the identities to the cryptographic keys
of a user.
This function needs to implement the following signature:
`RemoteUser fetchUser(string)`

Assuming `PubA` and `PrivA` are PEM-encoded public/private keys of a user, the following code
is a complete example of how to use the library:

 ```go
package main

import (
	"fmt"
	"github.com/haggj/go-it-crypto/itcrypto"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
)

var PubCa = `-----BEGIN CERTIFICATE-----
MIIBITCByAIJAJIgM6o1Soz/MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASz
mmKWEqdfYOcspvWpjyZlzDRj4ueX+VBMIh6PnyTDiF21CD9V/hCeJGMUBwOhA/0K
GBXjuHoEQWolytkNC4IdMAoGCCqGSM49BAMCA0gAMEUCIQCqtjjokBqyMe3h850n
HlXsfCDTLQe+Tq0YGX1s3Ac5zAIgW02bMx6mroNrFONplm6Li0HLIgCfXVOIS3BF
RQUGwhY=
-----END CERTIFICATE-----`

var PubA = `-----BEGIN CERTIFICATE-----
MIIBJzCBzwIJAPi05h3+oZR3MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowIDEeMBwG
A1UEAwwVIm1vaXRvcjJAbW9uaXRvci5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEBshF/Y40TAHRdcLc8CU9iu+ZJz8W69Qrmbttu/i9WAMR8sX+sF/glcOS
5BmltKxfL49B5jBZmVenmyajT6tfITAKBggqhkjOPQQDAgNHADBEAiAXvw+CwR97
ahXX2PPRJq/gQ2gXS/x0pvKNo6521UutlgIgdOknrMA6v+SglkBu8USsKGRgqFa2
RCNGeW9w1K4rnPY=
-----END CERTIFICATE-----`

var PrivA = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNxkH9Z8yVF7KHrLw
KP6IxRk1DYjHS6pYC8tXacYkizyhRANCAAQGyEX9jjRMAdF1wtzwJT2K75knPxbr
1CuZu227+L1YAxHyxf6wX+CVw5LkGaW0rF8vj0HmMFmZV6ebJqNPq18h
-----END PRIVATE KEY-----`

func fetchUser(id string) user.RemoteUser {
	/*
	   Resolve id to RemoteUser object.
	   Usually this function requests your API to fetch user keys.
	*/

	if id == "monitor" {
		monitor, err := user.ImportRemoteUser("monitor", PubA, PubA, true, PubCa)

		if err == nil {
			return monitor
		}
		panic("Can not import user: " + err.Error())
	}
	panic("No user found: " + id)
}

func main() {

	// This code initializes the it-crypto library with the private key pubA and secret key privA.
	itCrypto := itcrypto.ItCrypto{FetchUser: fetchUser}
	itCrypto.Login("monitor", PubA, PubA, PrivA, PrivA)

	// The logged-in user can create singed logs.
	signedLog, err := itCrypto.SignLog(logs.AccessLog{
		Monitor:       "monitor",
		Owner:         "owner",
		Tool:          "Tool",
		Justification: "Jus",
		Timestamp:     30,
		AccessKind:    "Aggregate",
		DataType:      []string{"Email", "Address"},
	})
	if err != nil {
		panic("Could not sign log data.")
	}

	// The logged-in user can encrypt the logs for others.
	owner, err := user.GenerateAuthenticatedUserById("owner")
	if err != nil {
		panic("Could not generate user.")
	}
	jwe, err := itCrypto.EncryptLog(signedLog, []user.RemoteUser{owner.RemoteUser})
	if err != nil {
		panic("Could not encrypt log.")
	}

	// The logged-in user can decrypt logs intended for him
	itCrypto.User = &owner
	receivedSingedLog, err := itCrypto.DecryptLog(jwe)
	if err != nil {
		panic("Could not decrypt log.")
	}
	receivedLog, err := receivedSingedLog.Extract()
	if err != nil {
		panic("Could extract raw log.")
	}
	fmt.Println(receivedLog)

}
 ```

# Development

## Running tests

```bash
CGO_ENABLED=0  go test -v ./...
```

## Update go package

1. Commit changes
2. Tag new version: `git tag v1.2.3`
3. Push version `git push origin v1.2.3`
4. Push version to package index `GOPROXY=proxy.golang.org go list -m github.com/haggj/go-it-crypto@v1.2.3`

# References
<a id="1">[1]</a>
Zieglmeier, Valentin and Pretschner, Alexander (2021).
Trustworthy transparency by design (2021).
https://arxiv.org/pdf/2103.10769.pdf