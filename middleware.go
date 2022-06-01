package main

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type requestIDCtxKey struct{}
type sessionStoreCtxKey struct{}

// baseMiddleware should wrap all requests to the service
func baseMiddleware(wrapped http.Handler,
	logger logrus.FieldLogger,
	sess *sessionManager,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		st := time.Now()

		// TODO - determine if we're in a place to trust this
		rid := r.Header.Get("X-Request-Id") // lambda
		if rid == "" {
			rid = uuid.NewString()
		}
		ctx = context.WithValue(ctx, requestIDCtxKey{}, rid)

		l := logger.WithField("request_id", rid)
		ctx = contextWithLogger(ctx, l)

		s, err := sess.sessionForRequest(r)
		if err != nil {
			// TODO - nice errors here
			l.WithError(err).Error("getting session")
			http.Error(w, "getting session", http.StatusInternalServerError)
			return
		}
		ctx = context.WithValue(ctx, sessionStoreCtxKey{}, s)

		ww := &wrapResponseWriter{
			ctx: ctx,

			ResponseWriter: w,

			smgr: sess,
			sess: s,
		}

		wrapped.ServeHTTP(ww, r.WithContext(ctx))

		// in lambda mode, handlers that write no repsonse return a status code
		// of 0 and no data which breaks things. Normal go has handlers for that:
		// * https://github.com/golang/go/blob/b59467e0365776761c3787a4d541b5e74fe24b24/src/net/http/server.go#L1971
		// * https://github.com/golang/gofrontend/blob/33f65dce43bd01c1fa38cd90a78c9aea6ca6dd59/libgo/go/net/http/server.go#L1603-L1624
		// mimic the bare minimum we need here to maybe lambda happy.

		if ww.st == 0 {
			// nothing has written to it. write a status
			ww.WriteHeader(http.StatusOK)
		}

		l.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   ww.st,
			"duration": time.Since(st),
		}).Info()
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
	if !w.sessSaved {
		if err := w.smgr.saveSession(w.ctx, w, w.sess); err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return 0, errors.Wrap(err, "Error saving session in hooked writer")
		}
	}
	w.sessSaved = true

	return w.ResponseWriter.Write(b)
}
