package user

import (
	"encoding/json"

	. "github.com/aeznir/go-it-crypto/error"
	. "github.com/aeznir/go-it-crypto/logs"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
)

func Encrypt(jwsSignedLog SingedAccessLog, sender AuthenticatedUser, receivers []RemoteUser) (string, error) {

	uuid := uuid.New().String()

	// Embed signed AccessLog into a SharedLog object and sign this object -> jwsSharedLog
	sharedLog := SharedLog{Log: jwsSignedLog, ShareId: uuid, Creator: sender.Id}

	data, err := json.Marshal(sharedLog)
	if err != nil {
		return "", ItCryptoError{Des: "Could not serialize sharedLog.", Err: err}
	}

	jwsSharedLog, err := sender.SignData(data)
	if err != nil {
		return "", ItCryptoError{Des: "Could not sign sharedLog.", Err: err}
	}

	// Sender creates and signs the header -> jwsSharedHeader
	var receiverIds []string
	for _, receiver := range receivers {
		receiverIds = append(receiverIds, receiver.Id)
	}

	accessLog, err := FromSingedAccessLog(jwsSignedLog)
	if err != nil {
		return "", ItCryptoError{Des: "Could not read provided accessLog.", Err: err}
	}

	sharedHeader := SharedHeader{ShareId: uuid, Owner: accessLog.Owner, Receivers: receiverIds}

	data, err = json.Marshal(sharedHeader)
	if err != nil {
		return "", ItCryptoError{Des: "Could not serialize sharedHeader.", Err: err}
	}

	jwsSharedHeader, err := sender.SignData(data)
	if err != nil {
		return "", ItCryptoError{Des: "Could not sign sharedHeader.", Err: err}
	}

	// Sender creates the encrypted JWE
	var recipients []jose.Recipient
	for _, receiver := range receivers {
		recipients = append(recipients, jose.Recipient{
			Algorithm: jose.ECDH_ES_A256KW,
			Key:       &receiver.EncryptionCertificate,
		})
	}

	var options jose.EncrypterOptions
	var sharedHeaderObject interface{}
	json.Unmarshal([]byte(jwsSharedHeader), &sharedHeaderObject)
	options.WithHeader("sharedHeader", sharedHeaderObject)

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
