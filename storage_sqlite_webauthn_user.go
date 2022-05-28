package main

import "context"

var _ WebauthnUserStore = (*storage)(nil)

func (s *storage) GetUserByID(ctx context.Context, id string) (*DynamoWebauthnUser, bool, error) {
	panic("TODO")
}

func (s *storage) GetUserByEmail(ctx context.Context, email string) (*DynamoWebauthnUser, bool, error) {
	panic("TODO")
}

func (s *storage) PutUser(ctx context.Context, u *DynamoWebauthnUser) (id string, err error) {
	panic("TODO")
}

func (s *storage) ListUsers(ctx context.Context) ([]*DynamoWebauthnUser, error) {
	panic("TODO")
}

func (s *storage) DeleteUser(ctx context.Context, id string) error {
	panic("TODO")
}
