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
