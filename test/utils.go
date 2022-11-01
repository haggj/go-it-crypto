package test

import (
	"encoding/json"
	"fmt"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
	"github.com/stretchr/testify/assert"
	"testing"
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

var PubB = `-----BEGIN CERTIFICATE-----
MIIBITCByQIJAOuo8ugAq2wVMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv
cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD
VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
ELWdCySVeYt89xdfnUfbAh79CXk/gFvU8U988UpSLEAGx30aJ0ZecVpdKhlXO1G4
yiyL8Sl6dypeN8iH7g3EtTAJBgcqhkjOPQQBA0gAMEUCIQCFDtrX9Mog3KA904Yp
XduiWCtxVbGYGkSviklavTsNnAIgI8h9WNqHZdPJDVyhPwwS5oggTkGZah0LYfc3
8qphvbY=
-----END CERTIFICATE-----`

var PrivB = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9XQgYCk62PfcaOKE
OlAerYQAx0EWg4eVfqMc1amEu0ehRANCAAQQtZ0LJJV5i3z3F1+dR9sCHv0JeT+A
W9TxT3zxSlIsQAbHfRonRl5xWl0qGVc7UbjKLIvxKXp3Kl43yIfuDcS1
-----END PRIVATE KEY-----`

func CreateFetchUser(users []user.RemoteUser) user.FetchUser {
	return func(id string) user.RemoteUser {
		for _, user := range users {
			if id == user.Id {
				return user
			}
		}
		panic(fmt.Sprintf("No matching user found (%s)", id))
	}
}

func VerifyAccessLogs(t *testing.T, first logs.AccessLog, second logs.AccessLog) {
	firstRaw, _ := json.Marshal(first)
	secondRaw, _ := json.Marshal(second)
	assert.Equal(t, string(firstRaw), string(secondRaw))
}
