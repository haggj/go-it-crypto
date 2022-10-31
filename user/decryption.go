package user

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	. "github.com/aeznir/go-it-crypto/error"
	. "github.com/aeznir/go-it-crypto/logs"
	"gopkg.in/square/go-jose.v2"
)

type fetchUser func(string) RemoteUser

func Decrypt(jwe string, receiver AuthenticatedUser, fetchUser fetchUser) (SingedAccessLog, error) {

	// Parse and decrypt the given JWE
	object, err := jose.ParseEncrypted(jwe)
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Failed to parse JWE", Err: err}
	}

	_, header, plaintext, err := object.DecryptMulti(receiver.DecryptionKey)
	if err != nil {
		panic(err)
	}

	// Parse the jwsSharedHeader which is stored within the JWE protected header
	fmt.Println(header)
	if _, ok := header.ExtraHeaders["sharedHeader"]; !ok {
		return SingedAccessLog{}, ItCryptoError{Des: "Could not extract jwsSharedHeader", Err: nil}
	}
	jwsSharedHeader, err := JwsFromMap(header.ExtraHeaders["sharedHeader"].(map[string]interface{}))
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Could not parse jwsSharedHeader", Err: nil}
	}

	// Parse the jwsSharedLog which is stored within the JWE plaintext
	var obj interface{}
	json.Unmarshal(plaintext, &obj)
	jwsSharedLog, err := JwsFromBytes(plaintext)
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Could not parse jwsSharedLog", Err: nil}
	}

	// Extract the creator specified within the SharedLog.
	// Both, the SharedLog and the SharedHeader, are expected to be signed by this creator.
	creator, err := claimedCreator(jwsSharedLog)
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Failed to extract creator", Err: err}
	}

	sharedHeader, err := verifySharedHeader(jwsSharedHeader, fetchUser(creator))
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Could not verify sharedHeader", Err: err}
	}

	sharedLog, err := verifySharedLog(jwsSharedLog, fetchUser(creator))
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Could not verify sharedHeader", Err: err}
	}

	// Extract the monitor specified within the AccessLog.
	// The AccessLog is expected to be signed by this monitor
	jwsAccessLog := sharedLog.Log
	monitor, err := claimedMonitor(jwsAccessLog)
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Failed to extract monitor", Err: err}
	}

	accessLog, err := verifyAccessLog(JWS(jwsAccessLog), fetchUser(monitor))
	if err != nil {
		return SingedAccessLog{}, ItCryptoError{Des: "Could not verify accessLog", Err: err}
	}

	/*
	   Invariants, which need to hold:
	   1. AccessLog.owner == SharedHeader.owner
	   2. SharedLog.creator == AccessLog.monitor || SharedLog.creator == AccessLog.owner
	   3. SharedHeader.shareId = SharedLog.shareId
	*/
	// Verify if shareIds are identical
	if sharedHeader.ShareId != sharedLog.ShareId {
		return SingedAccessLog{}, ItCryptoError{Des: "Malformed data: ShareIds do not match!"}
	}

	// Verify if sharedHeader contains correct owner
	if accessLog.Owner != sharedHeader.Owner {
		return SingedAccessLog{}, ItCryptoError{Des: "Malformed data: The owner of the AccessLog is not specified as owner in the SharedHeader!"}
	}

	// Verify if either accessLog.owner or accessLog.monitor shared the log
	if !(sharedLog.Creator == accessLog.Monitor || sharedLog.Creator == accessLog.Owner) {
		return SingedAccessLog{}, ItCryptoError{Des: "Malformed data: Only the owner or the monitor of the AccessLog are allowed to share."}
	}
	if sharedLog.Creator == accessLog.Monitor {
		if len(sharedHeader.Receivers) != 1 || sharedHeader.Receivers[0] != accessLog.Owner {
			return SingedAccessLog{}, ItCryptoError{Des: "Malformed data: Monitors can only share the data with the owner of the log."}
		}
	}

	return jwsAccessLog, nil

}

func claimedCreator(jwsSharedLog JWS) (string, error) {
	rawJson, err := base64.RawURLEncoding.DecodeString(jwsSharedLog.Payload)
	if err != nil {
		return "", ItCryptoError{Des: "Could not base64 decode payload in jwsSharedLog", Err: err}
	}
	sharedLog, err := SharedLogFromJson(rawJson)
	if err != nil {
		return "", ItCryptoError{Des: "Could not deserialize payload in jwsSharedLog", Err: nil}
	}
	return sharedLog.Creator, nil
}

func claimedMonitor(jwsAccessLog SingedAccessLog) (string, error) {
	rawJson, err := base64.RawURLEncoding.DecodeString(jwsAccessLog.Payload)
	if err != nil {
		return "", ItCryptoError{Des: "Could not base64 decode payload in jwsAccessLog", Err: err}
	}
	accessLog, err := AccessLogFromJson(rawJson)
	if err != nil {
		return "", ItCryptoError{Des: "Could not deserialize payload in jwsAccessLog", Err: nil}
	}
	return accessLog.Monitor, nil
}

func verifySharedHeader(jwsSharedHeader JWS, sender RemoteUser) (SharedHeader, error) {

	// Parse JWS into correct object
	verify, err := jwsSharedHeader.ToJsonWebSignature()
	if err != nil {
		return SharedHeader{}, ItCryptoError{Des: "Could not parse JWS", Err: err}
	}

	// Verify signature of passed jwsSharedHeader
	payload, err := verify.Verify(&sender.VerificationCertificate)
	if err != nil {
		return SharedHeader{}, ItCryptoError{Des: "Could not verify signature of jwsSharedLog", Err: err}
	}

	// Parse payload into SharedHeader object
	sharedHeader, err := SharedHeaderFromJson(payload)
	if err != nil {
		return SharedHeader{}, ItCryptoError{Des: "Could not deserialize payload in jwsSharedHeader", Err: nil}
	}
	return sharedHeader, nil
}

func verifySharedLog(jwsSharedLog JWS, sender RemoteUser) (SharedLog, error) {

	// Parse JWS into correct object
	verify, err := jwsSharedLog.ToJsonWebSignature()
	if err != nil {
		return SharedLog{}, ItCryptoError{Des: "Could not parse JWS", Err: err}
	}

	// Verify signature of passed jwsSharedHeader
	payload, err := verify.Verify(&sender.VerificationCertificate)
	if err != nil {
		return SharedLog{}, ItCryptoError{Des: "Could not verify signature of jwsSharedLog", Err: err}
	}

	// Parse payload into SharedHeader object
	sharedLog, err := SharedLogFromJson(payload)
	if err != nil {
		return SharedLog{}, ItCryptoError{Des: "Could not deserialize payload in jwsSharedLog", Err: nil}
	}
	return sharedLog, nil
}

func verifyAccessLog(jwsAccessLog JWS, sender RemoteUser) (AccessLog, error) {

	// Parse JWS into correct object
	verify, err := jwsAccessLog.ToJsonWebSignature()
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not parse JWS", Err: err}
	}

	// Verify signature of passed jwsAccessLog
	payload, err := verify.Verify(&sender.VerificationCertificate)
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not verify signature of jwsAccessLog", Err: err}
	}

	// Parse payload into SharedHeader object
	accessLog, err := AccessLogFromJson(payload)
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not deserialize payload in jwsAccessLog", Err: nil}
	}
	return accessLog, nil
}
