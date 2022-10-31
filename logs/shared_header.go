package logs

import "encoding/json"

type SharedHeader struct {
	ShareId   string   `json:"shareId"`
	Owner     string   `json:"owner"`
	Receivers []string `json:"receivers"`
}

func SharedHeaderFromJson(data []byte) (SharedHeader, error) {
	var sharedHeader = SharedHeader{}
	err := json.Unmarshal(data, &sharedHeader)
	if err != nil {
		return SharedHeader{}, err
	}

	return sharedHeader, nil
}
