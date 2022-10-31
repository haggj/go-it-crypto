package logs

import (
	"encoding/base64"
	"encoding/json"

	. "github.com/aeznir/go-it-crypto/error"
	"gopkg.in/square/go-jose.v2"
)

type SingedAccessLog JWS

type JWS struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Header    string `json:"header,omitempty"`
	Protected string `json:"protected"`
}

func JwsFromBytes(data []byte) (JWS, error) {
	var obj JWS
	json.Unmarshal(data, &obj)
	return obj, nil
}

func JwsFromMap(data map[string]interface{}) (JWS, error) {
	rawJson, err := json.Marshal(data)
	if err != nil {
		return JWS{}, ItCryptoError{Des: "Failed to serialize provided map", Err: err}
	}
	var obj JWS
	json.Unmarshal(rawJson, &obj)
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

func (jwsAccessLog SingedAccessLog) Extract() (AccessLog, error) {
	rawJson, err := base64.RawURLEncoding.DecodeString(jwsAccessLog.Payload)
	if err != nil {
		return AccessLog{}, ItCryptoError{Des: "Could not base64 decode payload in jwsAccessLog", Err: err}
	}
	return AccessLogFromJson(rawJson)
}
