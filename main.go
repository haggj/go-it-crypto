package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/aeznir/go-it-crypto/logs"
	"github.com/aeznir/go-it-crypto/user"
	"gopkg.in/square/go-jose.v2"
)

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

func main() {
	fmt.Println("Hello, Modules!")

	// Generate a public/private key pair to use for this example.
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Generate a public/private key pair to use for this example.
	// privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey1 := &privateKey1.PublicKey
	encrypter, err := jose.NewMultiEncrypter(jose.A256GCM, []jose.Recipient{
		{Algorithm: jose.ECDH_ES_A256KW, Key: publicKey1}, {Algorithm: jose.ECDH_ES_A256KW, Key: publicKey1}}, nil)
	if err != nil {
		panic(err)
	}

	// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	var plaintext = []byte("Lorem ipsum dolor sit amet")
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// Serialize the encrypted object using the full serialization format.
	// Alternatively you can also use the compact format here by calling
	// object.CompactSerialize() instead.
	serialized := object.FullSerialize()

	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err = jose.ParseEncrypted(serialized)
	if err != nil {
		panic(err)
	}

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate that the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	_, _, _, err = object.DecryptMulti(privateKey1)
	if err != nil {
		panic(err)
	}

	_, _, _, err = object.DecryptMulti(privateKey1)
	if err != nil {
		panic(err)
	}

	accessLog := logs.GenerateAccessLog()

	remote1, err := user.GenerateRemoteUser()
	if err != nil {
		panic(err)
	}

	remote2, err := user.ImportRemoteUser(pubA, pubA)
	if err != nil {
		panic(err)
	}

	auth, err := user.ImportAuthenticatedUser(
		pubA, pubA, privA, privA,
	)
	auth, err = user.GenerateAuthenticatedUser()
	if err != nil {
		panic(err)
	}

	res, err := auth.SignAccessLog(accessLog)
	if err != nil {
		panic(err)
	}

	cipher, err := auth.Encrypt(res, []user.RemoteUser{remote1, remote2})
	if err != nil {
		panic(err)
	}
	fmt.Println(cipher)

}
