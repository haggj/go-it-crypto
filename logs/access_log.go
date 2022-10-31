package logs

import (
	b64 "encoding/base64"
	"encoding/json"
)

type AccessLog struct {
	Monitor       string   `json:"monitor"`
	Owner         string   `json:"owner"`
	Tool          string   `json:"tool"`
	Justification string   `json:"justification"`
	Timestamp     int      `json:"timestamp"`
	AccessKind    string   `json:"accessKind"`
	DataType      []string `json:"dataType"`
}

func GenerateAccessLog() AccessLog {
	return AccessLog{
		Monitor:       "Monitor",
		Owner:         "Owner",
		Tool:          "Tool",
		Justification: "Jus",
		Timestamp:     30,
		AccessKind:    "Aggregate",
		DataType:      []string{"Email", "Address"},
	}
}

func AccessLogFromJson(data []byte) (AccessLog, error) {
	var accessLog = AccessLog{}
	err := json.Unmarshal(data, &accessLog)
	if err != nil {
		return AccessLog{}, err
	}

	return accessLog, nil
}

func FromSingedAccessLog(signedLog SingedAccessLog) (AccessLog, error) {
	jsonData, err := b64.RawURLEncoding.DecodeString(signedLog.Payload)
	if err != nil {
		return AccessLog{}, err
	}

	var accessLog = AccessLog{}
	err = json.Unmarshal(jsonData, &accessLog)
	if err != nil {
		return AccessLog{}, err
	}

	return accessLog, nil
}
