package storage

import (
	"bytes"
	"context"

	"github.com/golang/protobuf/ptypes"
	"github.com/pkg/errors"

	"github.com/lstoll/idp/storage/storagepb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/lstoll/idp/webauthn/webauthnpb"
)

const (
	userNS          = "webauthn-users"
	authenticatorNS = "webauthn-authenticators"
)

var _ webauthnpb.WebAuthnUserServiceServer = (*UserStore)(nil)

// UserStore is a simple UserAuthenticator implementation backing onto the
// storage interface the rest of the IDP uses
type UserStore struct {
	// Storage to back on. We use the server directly, because we'll run
	// in-process with it.
	Storage storagepb.StorageServer
}

// GetUser returns the user for the given ID
func (u *UserStore) GetUser(ctx context.Context, req *webauthnpb.GetUserRequest) (*webauthnpb.GetUserResponse, error) {
	uresp, err := u.Storage.Get(ctx, &storagepb.GetRequest{Keyspace: userNS, Keys: []string{req.Username}})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, err
		}
		return nil, status.Error(codes.Internal, "Error looking up user")
	}
	wu := webauthnpb.WebauthnUser{}
	if err := ptypes.UnmarshalAny(uresp.Items[0].Object, &wu); err != nil {
		return nil, status.Error(codes.Internal, "Failed to unmarshal user object")
	}
	return &webauthnpb.GetUserResponse{User: &wu}, nil
}

// AddAuthenticatorToUser should associate the given user with the given
// authenticator
func (u *UserStore) AddAuthenticatorToUser(ctx context.Context, req *webauthnpb.AddAuthenticatorRequest) (*empty.Empty, error) {
	ur, err := u.GetUser(ctx, &webauthnpb.GetUserRequest{Username: req.Username})
	if err != nil {
		return nil, err
	}

	ua, err := ptypes.MarshalAny(ur.User)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to marshal user")
	}

	aa, err := ptypes.MarshalAny(req.Authenticator)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to marshal authenticator")
	}

	mut := &storagepb.MutateRequest{
		Mutations: []*storagepb.Mutation{
			{
				Mutation: &storagepb.Mutation_PutItem{
					PutItem: &storagepb.Item{
						Keyspace: userNS,
						Key:      ur.User.Username,
						Object:   ua,
					},
				},
			},
			{
				Mutation: &storagepb.Mutation_PutItem{
					PutItem: &storagepb.Item{
						Keyspace: authenticatorNS,
						Key:      string(req.Authenticator.Id),
						Object:   aa,
					},
				},
			},
		},
	}

	if _, err := u.Storage.Mutate(ctx, mut); err != nil {
		return nil, errors.Wrap(err, "Failed to store user/authenticator association")
	}

	return &empty.Empty{}, nil
}

// UserAuthenticators should return all the authenticators registered to the
// given user
func (u *UserStore) UserAuthenticators(ctx context.Context, req *webauthnpb.GetUserRequest) (*webauthnpb.GetAuthenticatorsResponse, error) {
	uresp, err := u.GetUser(ctx, req)
	if err != nil {
		return nil, err
	}

	ret := &webauthnpb.GetAuthenticatorsResponse{}

	for _, id := range uresp.User.AuthenticatorIds {
		aresp, err := u.GetAuthenticator(ctx, &webauthnpb.GetAuthenticatorRequest{AuthenticatorId: id})
		if err != nil {
			return nil, err
		}
		ret.Authenticators = append(ret.Authenticators, aresp.Authenticator)
	}

	return ret, nil
}

// GetAuthenticator returns the authenticator matching the provided ID
func (u *UserStore) GetAuthenticator(ctx context.Context, req *webauthnpb.GetAuthenticatorRequest) (*webauthnpb.GetAuthenticatorResponse, error) {
	aresp, err := u.Storage.Get(ctx, &storagepb.GetRequest{Keyspace: authenticatorNS, Keys: []string{string(req.AuthenticatorId)}})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, err
		}
		return nil, status.Error(codes.Internal, "Error looking up user")
	}
	wa := webauthnpb.WebauthnAuthenticator{}
	if err := ptypes.UnmarshalAny(aresp.Items[0].Object, &wa); err != nil {
		return nil, status.Error(codes.Internal, "Failed to unmarshal user object")
	}
	return &webauthnpb.GetAuthenticatorResponse{Authenticator: &wa}, nil
}

// DeleteAuthenticator removes the authenticator from the system
func (u *UserStore) DeleteAuthenticator(ctx context.Context, req *webauthnpb.DeleteAuthenticatorRequest) (*empty.Empty, error) {
	ar, err := u.GetAuthenticator(ctx, &webauthnpb.GetAuthenticatorRequest{AuthenticatorId: req.AuthenticatorId})
	if err != nil {
		return nil, err
	}

	ur, err := u.GetUser(ctx, &webauthnpb.GetUserRequest{Username: ar.Authenticator.Username})
	if err != nil {
		return nil, err
	}
	for i, a := range ur.User.AuthenticatorIds {
		if bytes.Compare(a, req.AuthenticatorId) == 0 {
			ur.User.AuthenticatorIds = append(ur.User.AuthenticatorIds[:i], ur.User.AuthenticatorIds[i+1:]...)
			break
		}
	}
	ua, err := ptypes.MarshalAny(ur.User)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to marshal user")
	}

	mut := &storagepb.MutateRequest{
		Mutations: []*storagepb.Mutation{
			{
				Mutation: &storagepb.Mutation_PutItem{
					PutItem: &storagepb.Item{
						Keyspace: userNS,
						Key:      ur.User.Username,
						Object:   ua,
					},
				},
			},
			{
				Mutation: &storagepb.Mutation_DeleteItem{
					DeleteItem: &storagepb.DeleteItem{
						Keyspace: authenticatorNS,
						Key:      string(req.AuthenticatorId),
					},
				},
			},
		},
	}

	if _, err := u.Storage.Mutate(ctx, mut); err != nil {
		return nil, errors.Wrap(err, "Failed to store user/authenticator association")
	}

	return &empty.Empty{}, nil
}
