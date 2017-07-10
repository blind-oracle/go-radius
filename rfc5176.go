// (c) Novgorodov

package radius

import (
    "strconv"
)

type ErrorCause uint32

func (v ErrorCause) String() string {
    switch v {
	case 503:
	    return "Session-Context-Not-Found (503)"
	break
	
	case 406:
	    return "Unsupported-Extension (406)"
	break
    }
    
    return "Unknown-Error-Cause (" + strconv.Itoa(int(v)) + ")"
}

const (
    ErrorCauseSessionContextNotFound	ErrorCause = 503
    ErrorCauseUnsupportedExtension	ErrorCause = 406
)

func init() {
    builtinOnce.Do(initDictionary)
    
    Builtin.MustRegister("Error-Cause", 101, AttributeInteger)
}
