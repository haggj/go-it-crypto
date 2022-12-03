package logs

import (
	b64 "encoding/base64"
	"encoding/json"
)

// AccessLog represents a raw log, which is not signed by a monitor.
type AccessLog struct {
	Monitor       string   `json:"monitor"`
	Owner         string   `json:"owner"`
	Tool          string   `json:"tool"`
	Justification string   `json:"justification"`
	Timestamp     int      `json:"timestamp"`
	AccessKind    string   `json:"accessKind"`
	DataType      []string `json:"dataType"`
}

// GenerateAccessLog generates an exemplary log.
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

// AccessLogFromJson tries to parse the given json data into an AccessLog object.
func AccessLogFromJson(data []byte) (AccessLog, error) {
	var accessLog = AccessLog{}
	err := json.Unmarshal(data, &accessLog)
	if err != nil {
		return AccessLog{}, err
	}

	return accessLog, nil
}

// FromSingedLog tries to extract an AccessLog from the given SignedAccessLog.
// This does not involve any verification checks.
func FromSingedLog(signedLog SingedLog) (AccessLog, error) {
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
