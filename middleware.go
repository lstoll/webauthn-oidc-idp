package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
)

// baseMiddleware should wrap all requests to the service
func baseMiddleware(wrapped http.Handler,
	sessMgr *scs.SessionManager,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := time.Now()

		rid := uuid.NewString()
		r = r.WithContext(context.WithValue(r.Context(), "request_id", rid))

		ww := &wrapResponseWriter{
			ResponseWriter: w,
		}

		sessMgr.LoadAndSave(wrapped).ServeHTTP(w, r)

		slog.InfoContext(r.Context(), "",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", ww.status),
			slog.Duration("duration", time.Since(st)),
		)
	})
}

// httpErrHandler renders out nicer errors
type httpErrHandler struct {
}

func (h *httpErrHandler) Error(w http.ResponseWriter, r *http.Request, err error) {
	l := ctxLog(r.Context())
	l.Error(err)
	http.Error(w, "Internal Error", http.StatusInternalServerError)
}

func (h *httpErrHandler) BadRequest(w http.ResponseWriter, r *http.Request, message string) {
	http.Error(w, message, http.StatusBadRequest)
}

func (h *httpErrHandler) Forbidden(w http.ResponseWriter, r *http.Request, message string) {
	http.Error(w, message, http.StatusForbidden)
}

type wrapResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *wrapResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *wrapResponseWriter) Write(b []byte) (int, error) {
	return w.ResponseWriter.Write(b)
}
