package logs

type SharedHeader struct {
	ShareId   string   `json:"shareId"`
	Owner     string   `json:"owner"`
	Receivers []string `json:"receivers"`
}
