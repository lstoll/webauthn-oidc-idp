package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type (
	requestIDCtxKey    struct{}
	sessionStoreCtxKey struct{}
)

// baseMiddleware should wrap all requests to the service
func baseMiddleware(wrapped http.Handler, sess *sessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := time.Now()

		// TODO - determine if we're in a place to trust this
		rid := r.Header.Get("X-Request-Id") // lambda
		if rid == "" {
			rid = uuid.NewString()
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDCtxKey{}, rid))

		logger := slog.With(slog.String("request_id", rid))

		s, err := sess.sessionForRequest(r)
		if err != nil {
			// TODO - nice errors here
			logger.ErrorContext(r.Context(), "getting session", logErr(err))
			http.Error(w, "getting session", http.StatusInternalServerError)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionStoreCtxKey{}, s))

		ww := &wrapResponseWriter{
			ctx: r.Context(),

			ResponseWriter: w,

			smgr: sess,
			sess: s,
		}

		wrapped.ServeHTTP(ww, r)

		// run a save here to make sure we always save it, responses that write
		// nothing will miss the hook in `Write`
		if err := ww.saveSession(); err != nil {
			// the method handles user response etc.
			return
		}

		logger.Info("http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", ww.st),
			slog.Duration("duration", time.Since(st)))
	})
}

// sessionFromContext will return a reference to the HTTP session from the given
// (request, usually) context. it is guaranteed to return a session, either the
// current one or a fresh session. This session will be saved when the request
// closes.
func sessionFromContext(ctx context.Context) *webSession {
	return ctx.Value(sessionStoreCtxKey{}).(*webSession)
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
	// ctx for this request cycle, as we don't have access to it later.
	ctx context.Context

	http.ResponseWriter
	st int

	sessSaved bool
	smgr      *sessionManager
	sess      *webSession
}

func (w *wrapResponseWriter) WriteHeader(code int) {
	w.st = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *wrapResponseWriter) Write(b []byte) (int, error) {
	// we can't save the session after we write, so make sure it's saved.
	if err := w.saveSession(); err != nil {
		return 0, err
	}

	return w.ResponseWriter.Write(b)
}

func (w *wrapResponseWriter) saveSession() error {
	if !w.sessSaved {
		if err := w.smgr.saveSession(w.ctx, w, w.sess); err != nil {
			w.sessSaved = true // avoid looping on continual writes
			slog.ErrorContext(w.ctx, "saving session", logErr(err))
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			// TODO - would an EOF or connection closed error be better here, to make the failure final?
			return fmt.Errorf("error saving session in hooked writer: %w", err)
		}
	}
	w.sessSaved = true
	return nil
}
