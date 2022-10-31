package logs

import (
	"encoding/json"
)

type SharedLog struct {
	Log     SingedAccessLog `json:"log"`
	ShareId string          `json:"shareId"`
	Creator string          `json:"creator"`
}

func SharedLogFromJson(data []byte) (SharedLog, error) {
	var sharedLog = SharedLog{}
	err := json.Unmarshal(data, &sharedLog)
	if err != nil {
		return SharedLog{}, err
	}
	return sharedLog, nil
}
