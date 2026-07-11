// Package jsend builds small JSend response envelopes.
package jsend

// Envelope is one JSend response body.
type Envelope struct {
	Status  string `json:"status"`
	Data    any    `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// Success returns a JSend success envelope.
func Success(data any) Envelope {
	return Envelope{Status: "success", Data: data}
}

// Fail returns a JSend fail envelope.
func Fail(data any) Envelope {
	return Envelope{Status: "fail", Data: data}
}

// Error returns a JSend error envelope.
func Error(message, code string) Envelope {
	return Envelope{Status: "error", Message: message, Code: code}
}
