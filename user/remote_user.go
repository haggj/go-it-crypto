package user

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

type RemoteUser struct {
	Id                      string
	EncryptionCertificate   ecdsa.PublicKey
	VerificationCertificate ecdsa.PublicKey
}

func ImportRemoteUser(encryptionCertificate string, VerificationCertificate string) (RemoteUser, error) {

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
		EncryptionCertificate:   encryptionCertificate,
		VerificationCertificate: verificationCertificate,
	}, nil
}
