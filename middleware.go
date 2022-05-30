package main

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

type requestIDCtxKey struct{}
type sessionStoreCtxKey struct{}

// baseMiddleware should wrap all requests to the service
func baseMiddleware(wrapped http.Handler,
	logger logrus.FieldLogger,
	sess sessions.Store,
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

		// TODO - actually load a session here too, have a global session type
		// to make it "typed"
		ctx = context.WithValue(ctx, sessionStoreCtxKey{}, sess)

		ww := &wrapResponseWriter{ResponseWriter: w}

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

func sessionStoreFromContext(ctx context.Context) sessions.Store {
	return ctx.Value(sessionStoreCtxKey{}).(sessions.Store)
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

// wrapResponseWriter is our response writer we pass to callers. We hook in here
// to be able to log things, and set content type to work around the lack of
// detection on
// lambda(https://github.com/apex/gateway/blob/46d1104cd6db3bb9e0c0dcde71ddf15db8d87cf1/response.go#L54-L56)
type wrapResponseWriter struct {
	http.ResponseWriter
	st int
	wh bool
}

func (w *wrapResponseWriter) WriteHeader(code int) {
	if w.wh {
		return
	}
	w.st = code
	w.ResponseWriter.WriteHeader(code)
	w.wh = true
}

func (w *wrapResponseWriter) Write(b []byte) (int, error) {
	// TODO - could always save session here on the first run. This would allow
	// us to automatically handle the write, without habving each thing have to
	// do it manually. This would allow us to hook in to the last possible
	// moment for it
	if w.Header().Get("content-type") == "" {
		w.Header().Set("content-type", http.DetectContentType(b))
	}
	if w.st == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
