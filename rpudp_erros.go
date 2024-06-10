package prudp

import "errors"

var (
	errInvalidOperation = errors.New("invalid operation")
	errTimeout          = errors.New("timeout")
)
