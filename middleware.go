package main

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"go.uber.org/zap"
)

type loggerCtxKey struct{}
type requestIDCtxKey struct{}
type sessionStoreCtxKey struct{}

// baseMiddleware should wrap all requests to the service
func baseMiddleware(wrapped http.Handler,
	logger *zap.SugaredLogger,
	scHashKey []byte,
	scEncryptKey []byte,
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

		sl := logger.With("request_id", rid)
		ctx = context.WithValue(ctx, loggerCtxKey{}, rid)

		store := sessions.NewCookieStore(scHashKey, scEncryptKey)
		ctx = context.WithValue(ctx, sessionStoreCtxKey{}, store)

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

		sl.With(
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.st,
			"duration", time.Since(st),
		).Info()
	})
}

func loggerFromContext(ctx context.Context) *zap.SugaredLogger {
	l, ok := ctx.Value(loggerCtxKey{}).(*zap.SugaredLogger)
	if ok {
		return l
	}
	return zap.NewNop().Sugar()
}

func sessionStoreFromContext(ctx context.Context) sessions.Store {
	return ctx.Value(sessionStoreCtxKey{}).(sessions.Store)
}

// httpErrHandler renders out nicer errors
type httpErrHandler struct {
}

func (h *httpErrHandler) Error(w http.ResponseWriter, r *http.Request, err error) {
	l := loggerFromContext(r.Context())
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
	if w.Header().Get("content-type") == "" {
		w.Header().Set("content-type", http.DetectContentType(b))
	}
	if w.st == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
