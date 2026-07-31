package pairing

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
)

// PublicHandler exposes only claim lifecycle operations over pinned TLS.
func PublicHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/pairings/{id}/claim", func(writer http.ResponseWriter, request *http.Request) {
		bundle, err := store.Claim(request.PathValue("id"), bearer(request))
		writeResult(writer, bundle, err)
	})
	mux.HandleFunc("POST /v1/pairings/{id}/ready", func(writer http.ResponseWriter, request *http.Request) {
		record, err := store.Ready(request.PathValue("id"), bearer(request))
		writeResult(writer, stateResponse(record), err)
	})
	mux.HandleFunc("GET /v1/pairings/{id}", func(writer http.ResponseWriter, request *http.Request) {
		record, err := store.Status(request.PathValue("id"), bearer(request))
		writeResult(writer, stateResponse(record), err)
	})
	mux.HandleFunc("POST /v1/pairings/{id}/verified", func(writer http.ResponseWriter, request *http.Request) {
		record, err := store.Verified(request.PathValue("id"), bearer(request))
		writeResult(writer, stateResponse(record), err)
	})
	return secureHandler(mux)
}

// ControlHandler is served only on the protected local operator socket.
func ControlHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/pairings", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			ID            string           `json:"id"`
			Endpoint      string           `json:"endpoint"`
			CACertificate string           `json:"ca_certificate"`
			ServerName    string           `json:"server_name"`
			ExpiresAt     time.Time        `json:"expires_at"`
			Bundle        pairingv1.Bundle `json:"bundle"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeResult(writer, nil, errors.New("invalid create request"))
			return
		}
		certificate, err := base64.RawStdEncoding.DecodeString(input.CACertificate)
		if err != nil {
			writeResult(writer, nil, errors.New("invalid create request"))
			return
		}
		invitation, err := store.Create(InvitationOptions{ID: input.ID, Endpoint: input.Endpoint, CACertificate: certificate, ServerName: input.ServerName, ExpiresAt: input.ExpiresAt, Bundle: input.Bundle})
		writeResult(writer, struct {
			Invitation string `json:"invitation"`
		}{Invitation: invitation}, err)
	})
	mux.HandleFunc("GET /v1/pairings/{id}", func(writer http.ResponseWriter, request *http.Request) {
		record, err := store.LocalStatus(request.PathValue("id"))
		writeResult(writer, stateResponse(record), err)
	})
	mux.HandleFunc("POST /v1/pairings/{id}/activate", func(writer http.ResponseWriter, request *http.Request) {
		record, err := store.Activate(request.PathValue("id"))
		writeResult(writer, stateResponse(record), err)
	})
	mux.HandleFunc("DELETE /v1/pairings/{id}", func(writer http.ResponseWriter, request *http.Request) {
		err := store.Revoke(request.PathValue("id"))
		if err != nil {
			writeResult(writer, nil, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	return secureHandler(mux)
}

func secureHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, pairingv1.MaxMessageBytes)
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(writer, request)
		if request.Body != nil {
			_ = request.Body.Close()
		}
	})
}

func bearer(request *http.Request) string {
	scheme, value, found := strings.Cut(strings.TrimSpace(request.Header.Get("Authorization")), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

func writeResult(writer http.ResponseWriter, value any, err error) {
	if err != nil {
		switch {
		case errors.Is(err, ErrGone):
			http.Error(writer, "pairing is no longer available", http.StatusGone)
		case errors.Is(err, ErrForbidden):
			http.Error(writer, "pairing credential is invalid", http.StatusUnauthorized)
		case errors.Is(err, io.EOF), errors.Is(err, http.ErrBodyReadAfterClose):
			http.Error(writer, "invalid request", http.StatusBadRequest)
		default:
			http.Error(writer, "pairing request failed", http.StatusConflict)
		}
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(writer).Encode(value); encodeErr != nil {
		http.Error(writer, "encode response", http.StatusInternalServerError)
	}
}

func stateResponse(record Record) pairingv1.StateResponse {
	return pairingv1.StateResponse{APIVersion: pairingv1.APIVersion, PairingID: record.ID, State: record.State}
}
