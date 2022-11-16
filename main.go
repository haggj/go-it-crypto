package main

import (
	"fmt"
	"github.com/haggj/go-it-crypto/itcrypto"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
)

var PubCa = `-----BEGIN CERTIFICATE-----
MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0
aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4
SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV
vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z
HRVyXPs=
-----END CERTIFICATE-----`

var PubA = `-----BEGIN CERTIFICATE-----
MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv
cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD
VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh
QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs
+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk
kyxIiA==
-----END CERTIFICATE-----`

var PrivA = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY
2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP
oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz
-----END PRIVATE KEY-----`

func fetchUser(id string) user.RemoteUser {
	/*
	   Resolve id to RemoteUser object.
	   Usually this function requests your API to fetch user keys.
	*/

	if id == "monitor" {
		user, err := user.ImportRemoteUser("monitor", PubA, PubA, PubCa)

		if err == nil {
			return user
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
