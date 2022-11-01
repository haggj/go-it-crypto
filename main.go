package main

import (
	"fmt"

	. "github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
	. "github.com/haggj/go-it-crypto/user"
)

var rootCA = `-----BEGIN CERTIFICATE-----
MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0
aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4
SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV
vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z
HRVyXPs=
-----END CERTIFICATE-----`

var pubA = `-----BEGIN CERTIFICATE-----
MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv
cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD
VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh
QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs
+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk
kyxIiA==
-----END CERTIFICATE-----`

var privA = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY
2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP
oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz
-----END PRIVATE KEY-----`

var pubB = `-----BEGIN CERTIFICATE-----
MIIBITCByQIJAOuo8ugAq2wVMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv
cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD
VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
ELWdCySVeYt89xdfnUfbAh79CXk/gFvU8U988UpSLEAGx30aJ0ZecVpdKhlXO1G4
yiyL8Sl6dypeN8iH7g3EtTAJBgcqhkjOPQQBA0gAMEUCIQCFDtrX9Mog3KA904Yp
XduiWCtxVbGYGkSviklavTsNnAIgI8h9WNqHZdPJDVyhPwwS5oggTkGZah0LYfc3
8qphvbY=
-----END CERTIFICATE-----`

var privB = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9XQgYCk62PfcaOKE
OlAerYQAx0EWg4eVfqMc1amEu0ehRANCAAQQtZ0LJJV5i3z3F1+dR9sCHv0JeT+A
W9TxT3zxSlIsQAbHfRonRl5xWl0qGVc7UbjKLIvxKXp3Kl43yIfuDcS1
-----END PRIVATE KEY-----`

func main() {

	// Setup Users
	monitor, _ := user.GenerateAuthenticatedUser()
	owner, _ := user.GenerateAuthenticatedUser()
	receiver, _ := user.GenerateAuthenticatedUser()
	fetchUser := getFetchUser([]RemoteUser{monitor.RemoteUser, owner.RemoteUser})

	// 1. Step: Monitor creates log and encrypts it for owner
	accessLog := AccessLog{Monitor: monitor.Id, Owner: owner.Id, Tool: "tool", Justification: "jus", Timestamp: 30, AccessKind: "direct", DataType: []string{"Email", "Address"}}
	signedLog, _ := monitor.SignAccessLog(accessLog)
	jwe, _ := monitor.Encrypt(signedLog, []user.RemoteUser{owner.RemoteUser})
	fmt.Println(jwe)

	// 2. Step: Owner can decrypt log
	logOut, _ := owner.Decrypt(jwe, fetchUser)
	accessLog, _ = logOut.Extract()
	fmt.Println(accessLog)

	// 3. Step: Owner shares with receivers
	jwe, _ = owner.Encrypt(logOut, []RemoteUser{owner.RemoteUser, receiver.RemoteUser})

	// 4. Step: Owner and receiver can decrypt
	logOut, _ = owner.Decrypt(jwe, fetchUser)
	logOut, _ = receiver.Decrypt(jwe, fetchUser)
	plain, _ := logOut.Extract()
	fmt.Println(plain)

	// accessLog := GenerateAccessLog()
	// accessLog.Monitor = "sender"
	// accessLog.Owner = "receiver"
	// accessLog.Justification = "go-it-crypto"

	// receiver, err := user.ImportAuthenticatedUser("receiver", pubB, pubB, privB, privB)
	// if err != nil {
	// 	panic(err)
	// }

	// sender, err := user.ImportAuthenticatedUser(
	// 	"sender", pubA, pubA, privA, privA,
	// )
	// if err != nil {
	// 	panic(err)
	// }

	// // user, _ := user.GenerateAuthenticatedUser()

	// fetchUser := getFetchUser([]RemoteUser{receiver.RemoteUser, sender.RemoteUser})

	// fmt.Println(fetchUser("sender"))

	// res, err := sender.SignAccessLog(accessLog)
	// if err != nil {
	// 	panic(err)
	// }

	// cipher, err := receiver.Encrypt(res, []RemoteUser{receiver.RemoteUser, sender.RemoteUser})
	// if err != nil {
	// 	panic(ItCryptoError{Des: "Could not encrypt", Err: err})
	// }
	// fmt.Printf("%s\n", string(cipher))

	// plain, err := receiver.Decrypt(cipher, fetchUser)
	// if err != nil {
	// 	panic(ItCryptoError{Des: "Could not decrypt", Err: err})
	// }

	// fmt.Println(plain.Extract())

}

func getFetchUser(users []RemoteUser) FetchUser {
	return func(x string) RemoteUser {
		for _, user := range users {
			if x == user.Id {
				return user
			}
		}
		panic("No matching user found")
	}
}
