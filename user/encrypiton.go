package user

import (
	"encoding/json"
	. "github.com/haggj/go-it-crypto/error"
	. "github.com/haggj/go-it-crypto/logs"
	"gopkg.in/square/go-jose.v2"
)

func Encrypt(jwsSignedLog SingedAccessLog, sender AuthenticatedUser, receivers []RemoteUser) (string, error) {
	var receiverIds []string
	for _, receiver := range receivers {
		receiverIds = append(receiverIds, receiver.Id)
	}

	// Embed signed AccessLog into a SharedLog object and sign this object -> jwsSharedLog
	sharedLog := SharedLog{Log: jwsSignedLog, Recipients: receiverIds, Creator: sender.Id}

	data, err := json.Marshal(sharedLog)
	if err != nil {
		return "", ItCryptoError{Des: "Could not serialize sharedLog.", Err: err}
	}

	jwsSharedLog, err := sender.SignData(data)
	if err != nil {
		return "", ItCryptoError{Des: "Could not sign sharedLog.", Err: err}
	}

	// Sender creates the encrypted JWE
	accessLog, err := FromSingedAccessLog(jwsSignedLog)
	if err != nil {
		return "", ItCryptoError{Des: "Could not read provided accessLog.", Err: err}
	}

	var recipients []jose.Recipient
	for _, receiver := range receivers {
		recipients = append(recipients, jose.Recipient{
			Algorithm: jose.ECDH_ES_A256KW,
			Key:       receiver.EncryptionCertificate,
		})
	}

	var options jose.EncrypterOptions
	options.WithHeader("recipients", receiverIds).WithHeader("owner", accessLog.Owner)

	encrypter, err := jose.NewMultiEncrypter(jose.A256GCM, recipients, &options)
	if err != nil {
		return "", ItCryptoError{Des: "Could not instantiate encryption engine.", Err: err}
	}

	jwe, err := encrypter.Encrypt([]byte(jwsSharedLog))
	if err != nil {
		return "", ItCryptoError{Des: "Could not encrypt.", Err: err}
	}

	return jwe.FullSerialize(), nil
}
