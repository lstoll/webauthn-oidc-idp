package main

import "context"

var _ Storage = (*storage)(nil)

func (s *storage) Authenticate(ctx context.Context, sessionID string, auth Authentication) error {
	panic("TODO")
}

func (s *storage) GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error) {
	panic("TODO")
}
