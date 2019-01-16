package radius

import "fmt"

// ErrorCause represents an Error-Cause attribute
type ErrorCause uint32

func (v ErrorCause) String() string {
	switch v {
	case 503:
		return "Session-Context-Not-Found (503)"
	case 406:
		return "Unsupported-Extension (406)"
	}

	return fmt.Sprintf("Unknown-Error-Cause (%d)", v)
}

// Some common error causes
const (
	ErrorCauseSessionContextNotFound ErrorCause = 503
	ErrorCauseUnsupportedExtension   ErrorCause = 406
)

func init() {
	builtinOnce.Do(initDictionary)
	Builtin.MustRegister("Error-Cause", 101, AttributeInteger)
}
