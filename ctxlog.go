package main

import (
	"context"

	"github.com/sirupsen/logrus"
)

type loggerCtxKey struct{}

func ctxLog(ctx context.Context) logrus.FieldLogger {
	l, ok := ctx.Value(loggerCtxKey{}).(logrus.FieldLogger)
	if ok {
		return l
	}
	return logrus.New()
}

func contextWithLogger(ctx context.Context, l logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerCtxKey{}, l)
}
