package logs

type SharedLog struct {
	Log     SingedAccessLog `json:"log"`
	ShareId string          `json:"shareId"`
	Creator string          `json:"creator"`
}
