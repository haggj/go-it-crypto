package itcrypto

import (
	. "github.com/haggj/go-it-crypto/error"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
)

// ItCrypto provides convenient wrappers around the internal crypto operations.
// It can be used to sign, encrypt and decrypt logs.
type ItCrypto struct {
	FetchUser user.FetchUser
	User      *user.AuthenticatedUser
}

// Login logs a user in with its keys and certificates.
// This is required to sign, encrypt or decrypt data.
func (obj *ItCrypto) Login(id string, encryptionCertificate string, verificationCertificate string, decryptionKey string, signingKey string) error {
	user, err := user.ImportAuthenticatedUser(id, encryptionCertificate, verificationCertificate, decryptionKey, signingKey)
	if err != nil {
		return ItCryptoError{Des: "Could not improt user", Err: err}
	}
	obj.User = &user
	return nil
}

// EncryptLog encrypts the given log for the given receivers. The log must be singed by a monitor.
// This requires a logged-in user. The function returns a JWE token encoded as string.
func (obj *ItCrypto) EncryptLog(log logs.SingedLog, receivers []user.RemoteUser) (string, error) {
	if obj.User == nil {
		return "", ItCryptoError{Des: "Before you can encrypt you need to login a user"}
	}
	return obj.User.EncryptLog(log, receivers)
}

// DecryptLog decrypts the given JWE token. This requires a logged-in user.
func (obj *ItCrypto) DecryptLog(jwe string) (logs.SingedLog, error) {
	if obj.User == nil {
		return logs.SingedLog{}, ItCryptoError{Des: "Before you can decrypt you need to login a user"}
	}
	if obj.FetchUser == nil {
		return logs.SingedLog{}, ItCryptoError{Des: "Before you can decrypt you need to provide FetchUser function"}
	}
	return obj.User.DecryptLog(jwe, obj.FetchUser)
}

// SignLog signs the provided raw log data (encoded as AccessLog). This requires a logged-in user.
func (obj *ItCrypto) SignLog(log logs.AccessLog) (logs.SingedLog, error) {
	if obj.User == nil {
		return logs.SingedLog{}, ItCryptoError{Des: "Before you can sign data you need to login a user"}
	}
	return obj.User.SignLog(log)
}
