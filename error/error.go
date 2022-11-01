package error

import "fmt"

type ItCryptoError struct {
	Des string
	Err error
}

func (e ItCryptoError) Error() string {
	var origin = ""
	if e.Err != nil {
		return fmt.Sprintf("%s\n\nReason:\n%s", e.Des, origin)
	}
	return e.Des
}
