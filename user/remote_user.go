package user

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/google/uuid"
)

type RemoteUser struct {
	Id                      string
	EncryptionCertificate   ecdsa.PublicKey
	VerificationCertificate ecdsa.PublicKey
}

func ImportRemoteUser(id string, encryptionCertificate string, VerificationCertificate string) (RemoteUser, error) {

	rawEncCert, _ := pem.Decode([]byte(encryptionCertificate))
	encCert, err := x509.ParseCertificate([]byte(rawEncCert.Bytes))
	if err != nil {
		return RemoteUser{}, nil
	}

	rawVrfCert, _ := pem.Decode([]byte(VerificationCertificate))
	vrfCert, err := x509.ParseCertificate([]byte(rawVrfCert.Bytes))
	if err != nil {
		return RemoteUser{}, nil
	}

	return RemoteUser{
		Id:                      id,
		EncryptionCertificate:   *encCert.PublicKey.(*ecdsa.PublicKey),
		VerificationCertificate: *vrfCert.PublicKey.(*ecdsa.PublicKey),
	}, nil
}

func GenerateRemoteUser() (RemoteUser, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RemoteUser{}, err
	}
	encryptionCertificate := privateKey.PublicKey

	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RemoteUser{}, err
	}
	verificationCertificate := privateKey.PublicKey

	return RemoteUser{
		Id:                      uuid.New().String(),
		EncryptionCertificate:   encryptionCertificate,
		VerificationCertificate: verificationCertificate,
	}, nil
}
