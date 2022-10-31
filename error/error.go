package error

import "fmt"

type ItCryptoError struct {
	Des string
	Err error
}

func (e ItCryptoError) Error() string {
	var origin = ""
	if e.Err != nil {
		origin = e.Err.Error()
	}
	return fmt.Sprintf("%s\n\nReason:\n%s: syntax error", e.Des, origin)
}
