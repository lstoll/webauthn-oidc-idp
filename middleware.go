package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/cookiesession"
)

type (
	requestIDCtxKey struct{}
)

// baseMiddleware should wrap all requests to the service
func baseMiddleware(wrapped http.Handler, wnsessmgr *cookiesession.Manager[webSession, *webSession]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := time.Now()

		// TODO - determine if we're in a place to trust this
		rid := r.Header.Get("X-Request-Id") // lambda
		if rid == "" {
			rid = uuid.NewString()
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDCtxKey{}, rid))

		logger := slog.With(slog.String("request_id", rid))

		ww := &wrapResponseWriter{
			ResponseWriter: w,
		}

		wnsessmgr.Wrap(
			wrapped,
		).ServeHTTP(ww, r)

		logger.Info("http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", ww.st),
			slog.Duration("duration", time.Since(st)))
	})
}

// httpErrHandler renders out nicer errors
type httpErrHandler struct{}

func (h *httpErrHandler) Error(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "http error", logErr(err))
	http.Error(w, "Internal Error", http.StatusInternalServerError)
}

func (h *httpErrHandler) BadRequest(w http.ResponseWriter, _ *http.Request, message string) {
	http.Error(w, message, http.StatusBadRequest)
}

func (h *httpErrHandler) Forbidden(w http.ResponseWriter, _ *http.Request, message string) {
	http.Error(w, message, http.StatusForbidden)
}

type wrapResponseWriter struct {
	http.ResponseWriter
	st int
}

func (w *wrapResponseWriter) WriteHeader(code int) {
	w.st = code
	w.ResponseWriter.WriteHeader(code)
}
