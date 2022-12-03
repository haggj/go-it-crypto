package logs

import (
	"encoding/json"
)

// SharedLog represents a shared log. It contains a nested log (which is singed by a monitor) and information
// about the creator and intended receivers. A json-encoded SharedLog is encrypted within a JWE token.
type SharedLog struct {
	Log        SingedLog `json:"log"`
	Recipients []string  `json:"recipients"`
	Creator    string    `json:"creator"`
}

func SharedLogFromJson(data []byte) (SharedLog, error) {
	var sharedLog = SharedLog{}
	err := json.Unmarshal(data, &sharedLog)
	if err != nil {
		return SharedLog{}, err
	}
	return sharedLog, nil
}
