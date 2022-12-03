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

// AuthenticatedUser represents an authenticated user, which has access to all private and public keys.
// Thus, this user has all capabilities of a RemoteUser because it contains a remote user a nested object.
// This user is additionally able to:
// - sign data using its signingKey
// - decrypt data using its decryptionKey
type AuthenticatedUser struct {
	RemoteUser
	DecryptionKey *ecdsa.PrivateKey
	SigningKey    *ecdsa.PrivateKey
}

// EncryptLog encrypts a SignedAccessLog for the given set of receivers.
func (user AuthenticatedUser) EncryptLog(log SingedLog, receivers []RemoteUser) (string, error) {
	return Encrypt(log, user, receivers)
}

// DecryptLog decrypts a given JWE token.
func (user AuthenticatedUser) DecryptLog(jwe string, fn FetchUser) (SingedLog, error) {
	return Decrypt(jwe, user, fn)
}

// SignData cryptographically signs the provided data.
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

// SignLog cryptographically signs a raw AccessLog object.
func (user AuthenticatedUser) SignLog(log AccessLog) (SingedLog, error) {
	rawLog, err := json.Marshal(log)
	if err != nil {
		return SingedLog{}, err
	}

	signedData, err := user.SignData(rawLog)
	if err != nil {
		return SingedLog{}, err
	}

	var singedLog = SingedLog{}
	err = json.Unmarshal([]byte(signedData), &singedLog)
	if err != nil {
		return SingedLog{}, err
	}
	return singedLog, nil
}

// ImportAuthenticatedUser imports a user based on its certificates and keys.
// The returned user can be used to sign and encrypt logs.
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
			IsMonitor:               false,
		},
		DecryptionKey: decKey.(*ecdsa.PrivateKey),
		SigningKey:    signKey.(*ecdsa.PrivateKey),
	}, nil

}

// GenerateAuthenticatedUser generates a random AuthenticatedUser. It is used during testing.
func GenerateAuthenticatedUser() (AuthenticatedUser, error) {
	return GenerateAuthenticatedUserById(uuid.New().String())
}

// GenerateAuthenticatedUserById generates a random AuthenticatedUser with the given identity. It is used during testing.
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
