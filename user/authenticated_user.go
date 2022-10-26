package user

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	. "github.com/aeznir/go-it-crypto/logs"
	"github.com/square/go-jose"
)

type AuthenticatedUser struct {
	RemoteUser
	DecryptionKey crypto.PublicKey
	SigningKey    crypto.PublicKey
}

func (user AuthenticatedUser) Encrypt(data SingedAccessLog, receivers []RemoteUser) (string, error) {

	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	var recipients []jose.Recipient
	for _, receiver := range receivers {
		recipients = append(recipients, jose.Recipient{
			Algorithm: jose.ECDH_ES_A256KW,
			Key:       &receiver.EncryptionCertificate,
		})
	}

	encrypter, err := jose.NewMultiEncrypter(jose.A256GCM, recipients, nil)
	if err != nil {
		return "", err
	}

	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	return object.FullSerialize(), nil
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

func (user AuthenticatedUser) SignAccessLog(log AccessLog) (SingedAccessLog, error) {
	rawLog, err := json.Marshal(user)
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

func ImportAuthenticatedUser(encryptionCertificate string, VerificationCertificate string, decryptionKey string, signingKey string) (AuthenticatedUser, error) {

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
			EncryptionCertificate:   *encCert.PublicKey.(*ecdsa.PublicKey),
			VerificationCertificate: *vrfCert.PublicKey.(*ecdsa.PublicKey),
		},
		DecryptionKey: decKey,
		SigningKey:    signKey,
	}, nil

}

func GenerateAuthenticatedUser() (AuthenticatedUser, error) {
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
			EncryptionCertificate:   encryptionCertificate,
			VerificationCertificate: verificationCertificate,
		},
		DecryptionKey: decryptionKey,
		SigningKey:    signingKey,
	}, nil
}
