package error

import "fmt"

type ItCryptoError struct {
	Des string
	Err error
}

func (e ItCryptoError) Error() string {
	return fmt.Sprintf("%s\n\nReason:\n%s: syntax error", e.Des, e.Err.Error())
}
