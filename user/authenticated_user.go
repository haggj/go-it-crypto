package user

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/google/uuid"
	. "github.com/haggj/go-it-crypto/logs"
	"gopkg.in/square/go-jose.v2"
)

type AuthenticatedUser struct {
	RemoteUser
	DecryptionKey *ecdsa.PrivateKey
	SigningKey    *ecdsa.PrivateKey
}

func (user AuthenticatedUser) EncryptLog(log SingedAccessLog, receivers []RemoteUser) (string, error) {
	return Encrypt(log, user, receivers)
}

func (user AuthenticatedUser) DecryptLog(jwe string, fn FetchUser) (SingedAccessLog, error) {
	return Decrypt(jwe, user, fn)
}

func (user AuthenticatedUser) SignData(data []byte) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: user.SigningKey}, nil)
	if err != nil {
		return "", err
	}

	object, err := signer.Sign(data)
	if err != nil {
		return "", err
	}

	return object.FullSerialize(), nil
}

func (user AuthenticatedUser) SignLog(log AccessLog) (SingedAccessLog, error) {
	rawLog, err := json.Marshal(log)
	if err != nil {
		return SingedAccessLog{}, err
	}

	signedData, err := user.SignData(rawLog)
	if err != nil {
		return SingedAccessLog{}, err
	}

	var singedLog = SingedAccessLog{}
	err = json.Unmarshal([]byte(signedData), &singedLog)
	if err != nil {
		return SingedAccessLog{}, err
	}
	return singedLog, nil
}

func ImportAuthenticatedUser(id string, encryptionCertificate string, VerificationCertificate string, decryptionKey string, signingKey string) (AuthenticatedUser, error) {

	// Parse PEM-encoded encryption certificate
	rawEncCert, _ := pem.Decode([]byte(encryptionCertificate))
	encCert, err := x509.ParseCertificate([]byte(rawEncCert.Bytes))
	if err != nil {
		return AuthenticatedUser{}, err
	}

	// Parse PEM-encoded verification certificate
	rawVrfCert, _ := pem.Decode([]byte(VerificationCertificate))
	vrfCert, err := x509.ParseCertificate([]byte(rawVrfCert.Bytes))
	if err != nil {
		return AuthenticatedUser{}, err
	}

	// Parse pem-encoded decryption key
	rawDecKey, _ := pem.Decode([]byte(decryptionKey))
	decKey, err := x509.ParsePKCS8PrivateKey(rawDecKey.Bytes)
	if err != nil {
		return AuthenticatedUser{}, err
	}

	// Parse pem-encoded signing key
	rawSignKey, _ := pem.Decode([]byte(signingKey))
	signKey, err := x509.ParsePKCS8PrivateKey(rawSignKey.Bytes)
	if err != nil {
		return AuthenticatedUser{}, err
	}

	return AuthenticatedUser{
		RemoteUser: RemoteUser{
			Id:                      id,
			EncryptionCertificate:   encCert.PublicKey.(*ecdsa.PublicKey),
			VerificationCertificate: vrfCert.PublicKey.(*ecdsa.PublicKey),
		},
		DecryptionKey: decKey.(*ecdsa.PrivateKey),
		SigningKey:    signKey.(*ecdsa.PrivateKey),
	}, nil

}

func GenerateAuthenticatedUser() (AuthenticatedUser, error) {
	return GenerateAuthenticatedUserById(uuid.New().String())
}

func GenerateAuthenticatedUserById(id string) (AuthenticatedUser, error) {
	decryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return AuthenticatedUser{}, err
	}
	encryptionCertificate := decryptionKey.PublicKey

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return AuthenticatedUser{}, err
	}
	verificationCertificate := signingKey.PublicKey

	return AuthenticatedUser{
		RemoteUser: RemoteUser{
			Id:                      id,
			EncryptionCertificate:   &encryptionCertificate,
			VerificationCertificate: &verificationCertificate,
		},
		DecryptionKey: decryptionKey,
		SigningKey:    signingKey,
	}, nil
}
