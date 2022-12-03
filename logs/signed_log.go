package logs

import (
	"encoding/base64"
	"encoding/json"

	"gopkg.in/square/go-jose.v2"

	. "github.com/haggj/go-it-crypto/error"
)

// SingedLog is a JWS token
type SingedLog JWS

// JWS represents a basic JSON Web Signature token.
type JWS struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Header    string `json:"header,omitempty"`
	Protected string `json:"protected"`
}

func JwsFromBytes(data []byte) (JWS, error) {
	var obj JWS
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return JWS{}, ItCryptoError{Des: "Failed to deserialized provided data", Err: err}
	}
	return obj, nil
}

func (jws JWS) ToJsonWebSignature() (jose.JSONWebSignature, error) {
	rawJson, err := json.Marshal(jws)
	if err != nil {
		return jose.JSONWebSignature{}, ItCryptoError{Des: "Failed to serialize JWS", Err: err}
	}
	sig, err := jose.ParseSigned(string(rawJson))
	if err != nil {
		return jose.JSONWebSignature{}, ItCryptoError{Des: "Failed to parse into JSONWebSignature", Err: err}
	}
	return *sig, nil
}

func (jwsAccessLog SingedLog) Extract() (AccessLog, error) {
	rawJson, err := base64.RawURLEncoding.DecodeString(jwsAccessLog.Payload)
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not base64 decode payload in jwsAccessLog", Err: err}
	}
	return AccessLogFromJson(rawJson)
}
