package user

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/google/uuid"
	. "github.com/haggj/go-it-crypto/error"
)

// RemoteUser represents a remote User, which has access to the certificates of the user.
// The certificates can be used to:
// - encrypt data for this user (encryptionCertificate)
// - verify data which was signed by this user (verificationCertificate)
//
// **NOTE**: Do not instantiate this interface by yourself since the provided  certificate need to be validated against a trusted CA.
// Use the *User.importRemoteUser()* function instead.
type RemoteUser struct {
	Id                      string
	EncryptionCertificate   *ecdsa.PublicKey
	VerificationCertificate *ecdsa.PublicKey
	IsMonitor               bool
}

// ImportRemoteUser imports a user based on its public certificates. This function also verifies if the provided
// certificates are singed by the trusted certificate authority.
func ImportRemoteUser(id string, encryptionCertificate string, VerificationCertificate string, isMonitor bool, trustedCertificate string) (RemoteUser, error) {

	rawTrustedCert, _ := pem.Decode([]byte(trustedCertificate))
	trustedCert, err := x509.ParseCertificate([]byte(rawTrustedCert.Bytes))

	// Parse encryption certificate
	rawEncCert, _ := pem.Decode([]byte(encryptionCertificate))
	encCert, err := x509.ParseCertificate([]byte(rawEncCert.Bytes))
	if err != nil {
		return RemoteUser{}, ItCryptoError{Des: "Can not parse encryption certificate", Err: err}
	}

	// Verify encryption certificate
	err = encCert.CheckSignatureFrom(trustedCert)
	if err != nil {
		return RemoteUser{}, ItCryptoError{Des: "Can not verify encryption certificate", Err: err}
	}

	// Parse verification certificate
	rawVrfCert, _ := pem.Decode([]byte(VerificationCertificate))
	vrfCert, err := x509.ParseCertificate([]byte(rawVrfCert.Bytes))
	if err != nil {
		return RemoteUser{}, ItCryptoError{Des: "Can not parse verification certificate", Err: err}
	}

	// Verify verification certificate
	err = encCert.CheckSignatureFrom(trustedCert)
	if err != nil {
		return RemoteUser{}, ItCryptoError{Des: "Can not verify verification certificate", Err: err}
	}

	return RemoteUser{
		Id:                      id,
		EncryptionCertificate:   encCert.PublicKey.(*ecdsa.PublicKey),
		VerificationCertificate: vrfCert.PublicKey.(*ecdsa.PublicKey),
		IsMonitor:               isMonitor,
	}, nil
}

// GenerateRemoteUser generates a random RemoteUser. It is used during testing.
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
		EncryptionCertificate:   &encryptionCertificate,
		VerificationCertificate: &verificationCertificate,
	}, nil
}
