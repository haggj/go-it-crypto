package logs

type AccessLog struct {
	Monitor       string
	Owner         string
	Tool          string
	Justification string
	Timestamp     int
	AccessKind    string
	DataType      []string
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

type SingedAccessLog struct {
	Payload   string
	Signature string
	Header    string
	Protected string
}
