package itcrypto

import (
	. "github.com/haggj/go-it-crypto/error"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
)

type ItCrypto struct {
	FetchUser         user.FetchUser
	AuthenticatedUser *user.AuthenticatedUser
}

func (obj *ItCrypto) Login(id string, encryptionCertificate string, verificationCertificate string, decryptionKey string, signingKey string) error {
	user, err := user.ImportAuthenticatedUser(id, encryptionCertificate, verificationCertificate, decryptionKey, signingKey)
	if err != nil {
		return ItCryptoError{Des: "Could not improt user", Err: err}
	}
	obj.AuthenticatedUser = &user
	return nil
}

func (obj *ItCrypto) Encrypt(log logs.SingedAccessLog, receivers []user.RemoteUser) (string, error) {
	if obj.AuthenticatedUser == nil {
		return "", ItCryptoError{Des: "Before you can encrypt you need to login a user"}
	}
	return obj.AuthenticatedUser.Encrypt(log, receivers)
}

func (obj *ItCrypto) Decrypt(jwe string) (logs.SingedAccessLog, error) {
	if obj.AuthenticatedUser == nil {
		return logs.SingedAccessLog{}, ItCryptoError{Des: "Before you can decrypt you need to login a user"}
	}
	if obj.FetchUser == nil {
		return logs.SingedAccessLog{}, ItCryptoError{Des: "Before you can decrypt you need to provide FetchUser function"}
	}
	return obj.AuthenticatedUser.Decrypt(jwe, obj.FetchUser)
}

func (obj *ItCrypto) SignAccessLog(log logs.AccessLog) (logs.SingedAccessLog, error) {
	if obj.AuthenticatedUser == nil {
		return logs.SingedAccessLog{}, ItCryptoError{Des: "Before you can sign data you need to login a user"}
	}
	return obj.AuthenticatedUser.SignAccessLog(log)
}
