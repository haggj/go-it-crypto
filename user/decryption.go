package user

import (
	"encoding/base64"
	"encoding/json"
	"golang.org/x/exp/slices"
	"reflect"

	. "github.com/haggj/go-it-crypto/error"
	. "github.com/haggj/go-it-crypto/logs"
	"gopkg.in/square/go-jose.v2"
)

type FetchUser func(string) RemoteUser

// Decrypt takes a given JWE token and decrypts it by means of the Inverse Transparency E2EE.
// It tries to decrypt the given token with the key material provided by the passed receiving user.
// This function returns a SignedAccessLog if all verification steps are successful.
func Decrypt(jwe string, receiver AuthenticatedUser, fetchUser FetchUser) (SingedLog, error) {

	// Parse and decrypt the given JWE
	object, err := jose.ParseEncrypted(jwe)
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Failed to parse JWE", Err: err}
	}

	_, header, plaintext, err := object.DecryptMulti(receiver.DecryptionKey)
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Failed to decrypt JWE", Err: err}
	}

	// Parse the jwsSharedLog which is stored within the JWE plaintext
	var obj interface{}
	err = json.Unmarshal(plaintext, &obj)
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Could not deserialize plaintext", Err: err}
	}
	jwsSharedLog, err := JwsFromBytes(plaintext)
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Could not parse jwsSharedLog", Err: err}
	}

	// Extract the creator specified within the SharedLog.
	// The SharedLog is expected to be signed by this creator.
	creator, err := claimedCreator(jwsSharedLog)
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Failed to extract creator", Err: err}
	}

	sharedLog, err := verifySharedLog(jwsSharedLog, fetchUser(creator))
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Could not verify sharedHeader", Err: err}
	}

	// Extract the monitor specified within the AccessLog.
	// The AccessLog is expected to be signed by this monitor
	jwsAccessLog := sharedLog.Log
	monitor, err := claimedMonitor(jwsAccessLog)
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Failed to extract monitor", Err: err}
	}

	accessLog, err := verifyAccessLog(JWS(jwsAccessLog), fetchUser(monitor))
	if err != nil {
		return SingedLog{}, ItCryptoError{Des: "Could not verify accessLog", Err: err}
	}

	// Verify that the recipients in the SharedLog are equal to the recipients in the metadata
	metaRecipientsRaw, ok := header.ExtraHeaders["recipients"].([]interface{})
	if !ok {
		return SingedLog{}, ItCryptoError{Des: "Could not extract recipients from metadata", Err: nil}
	}

	metaRecipients := make([]string, len(metaRecipientsRaw))
	for i := range metaRecipientsRaw {
		metaRecipients[i] = metaRecipientsRaw[i].(string)
	}

	if !reflect.DeepEqual(sharedLog.Recipients, metaRecipients) {
		return SingedLog{}, ItCryptoError{Des: "Malformed data: Sets of recipients are not equal!"}
	}

	// Verify that the decrypting user is part of the recipients
	if !slices.Contains(sharedLog.Recipients, receiver.Id) {
		return SingedLog{}, ItCryptoError{Des: "Malformed data: Decrypting user not specified in recipients!"}
	}

	// Verify that the owner in the AccessLog is equal to the owner in the metadata
	metaOwner, ok := header.ExtraHeaders["owner"].(string)
	if !ok {
		return SingedLog{}, ItCryptoError{Des: "Could not extract owner from metadata", Err: nil}
	}

	if metaOwner != accessLog.Owner {
		return SingedLog{}, ItCryptoError{Des: "Malformed data: The specified owners are not equal!", Err: nil}
	}

	// Verify if either accessLog.owner or accessLog.monitor shared the log
	if !(sharedLog.Creator == accessLog.Monitor || sharedLog.Creator == accessLog.Owner) {
		return SingedLog{}, ItCryptoError{Des: "Malformed data: Only the owner or the monitor of the AccessLog are allowed to share."}
	}
	if sharedLog.Creator == accessLog.Monitor {
		if len(sharedLog.Recipients) != 1 || sharedLog.Recipients[0] != accessLog.Owner {
			return SingedLog{}, ItCryptoError{Des: "Malformed data: Monitors can only share the data with the owner of the log."}
		}
	}

	return jwsAccessLog, nil
}

// claimedCreator tries to parse the provided JWS token into a SharedLog.
// If this is successful, the function returns the creator stored in the SharedLog object.
// *NOTE*: This function does not verify the JWS token by any means.
func claimedCreator(jwsSharedLog JWS) (string, error) {
	rawJson, err := base64.RawURLEncoding.DecodeString(jwsSharedLog.Payload)
	if err != nil {
		return "", ItCryptoError{Des: "Could not base64 decode payload in jwsSharedLog", Err: err}
	}
	sharedLog, err := SharedLogFromJson(rawJson)
	if err != nil {
		return "", ItCryptoError{Des: "Could not deserialize payload in jwsSharedLog", Err: err}
	}
	return sharedLog.Creator, nil
}

// claimedMonitor tries to parse the provided JWS token into a AccessLog.
// If this is successful, the function returns the monitor stored in the AccessLog object.
// *NOTE*: This function does not verify the JWS token by any means.
func claimedMonitor(jwsAccessLog SingedLog) (string, error) {
	rawJson, err := base64.RawURLEncoding.DecodeString(jwsAccessLog.Payload)
	if err != nil {
		return "", ItCryptoError{Des: "Could not base64 decode payload in jwsAccessLog", Err: err}
	}
	accessLog, err := AccessLogFromJson(rawJson)
	if err != nil {
		return "", ItCryptoError{Des: "Could not deserialize payload in jwsAccessLog", Err: err}
	}
	return accessLog.Monitor, nil
}

// verifySharedLog verifies if the provided JWS token is singed by the specified sender.
// It then tries to parse the JWS token into a SharedLog object.
func verifySharedLog(jwsSharedLog JWS, sender RemoteUser) (SharedLog, error) {

	// Parse JWS into correct object
	verify, err := jwsSharedLog.ToJsonWebSignature()
	if err != nil {
		return SharedLog{}, ItCryptoError{Des: "Could not parse JWS", Err: err}
	}

	// Verify signature of passed jwsSharedHeader
	payload, err := verify.Verify(sender.VerificationCertificate)
	if err != nil {
		return SharedLog{}, ItCryptoError{Des: "Could not verify signature of jwsSharedLog", Err: err}
	}

	// Parse payload into SharedHeader object
	sharedLog, err := SharedLogFromJson(payload)
	if err != nil {
		return SharedLog{}, ItCryptoError{Des: "Could not deserialize payload in jwsSharedLog", Err: err}
	}
	return sharedLog, nil
}

// verifyAccessLog verifies if the provided JWS token is singed by the specified sender.
// It then tries to parse the JWS token into a AccessLog object.
func verifyAccessLog(jwsAccessLog JWS, sender RemoteUser) (AccessLog, error) {
	if !sender.IsMonitor {
		return AccessLog{}, ItCryptoError{Des: "Claimed monitor is not authorized to sign logs.", Err: nil}
	}

	// Parse JWS into correct object
	verify, err := jwsAccessLog.ToJsonWebSignature()
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not parse JWS", Err: err}
	}

	// Verify signature of passed jwsAccessLog
	payload, err := verify.Verify(sender.VerificationCertificate)
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not verify signature of jwsAccessLog", Err: err}
	}

	// Parse payload into SharedHeader object
	accessLog, err := AccessLogFromJson(payload)
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not deserialize payload in jwsAccessLog", Err: err}
	}
	return accessLog, nil
}
