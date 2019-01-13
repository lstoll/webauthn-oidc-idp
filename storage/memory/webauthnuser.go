package memory

import (
	"bytes"
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/lstoll/idp/webauthn/webauthnpb"
)

const (
	userCredsNS     = "user-creds"
	userNS          = "users"
	authenticatorNS = "authenticator"
)

var _ webauthnpb.WebAuthnUserServiceServer = (*UserStore)(nil)

type User struct {
	Password       string
	User           *webauthnpb.WebauthnUser
	Authenticators []*webauthnpb.WebauthnAuthenticator
}

// UserStore is a simple UserAuthenticator implementation backing onto the IDP
// storage interface
type UserStore struct {
	// Users keyed by "username"
	Users map[string]*User
}

func NewUserStore() *UserStore {
	return &UserStore{Users: map[string]*User{}}
}

type storeUser struct {
	Password []byte `json:"password"`
	UserID   string `json:"user_id"`
}

// LoginUser should return a User object if username and password are
// correct
func (u *UserStore) LoginUser(_ context.Context, req *webauthnpb.LoginRequest) (*webauthnpb.LoginResponse, error) {
	usr, ok := u.Users[req.Username]
	if !ok {
		return nil, status.Error(codes.NotFound, "User not found")
	}
	if usr.Password != req.Password {
		return nil, status.Error(codes.Unauthenticated, "Invalid password")
	}
	return &webauthnpb.LoginResponse{
		User: usr.User,
	}, nil
}

// GetUser returns the user for the given ID
func (u *UserStore) GetUser(_ context.Context, req *webauthnpb.GetUserRequest) (*webauthnpb.GetUserResponse, error) {
	resp := &webauthnpb.GetUserResponse{}
	switch l := req.Lookup.(type) {
	case *webauthnpb.GetUserRequest_UserId:
		for _, usr := range u.Users {
			if usr.User.Id == l.UserId {
				resp.User = usr.User
				break
			}
		}
		if resp.User == nil {
			return nil, status.Error(codes.NotFound, "User not found")
		}
	case *webauthnpb.GetUserRequest_Username:
		usr, ok := u.Users[l.Username]
		if !ok {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		resp.User = usr.User
	default:
		return nil, status.Error(codes.InvalidArgument, "Bad lookup query")
	}
	return resp, nil
}

// AddAuthenticatorToUser should associate the given user with the given
// authenticator
func (u *UserStore) AddAuthenticatorToUser(_ context.Context, req *webauthnpb.AddAuthenticatorRequest) (*empty.Empty, error) {
	var user *User
	for _, usr := range u.Users {
		if usr.User.Id == req.UserId {
			user = usr
		}
	}
	if user == nil {
		return nil, status.Error(codes.NotFound, "User not found")
	}
	user.Authenticators = append(user.Authenticators, req.Authenticator)

	return &empty.Empty{}, nil
}

// UserAuthenticators should return all the authenticators registered to the
// given user
func (u *UserStore) UserAuthenticators(_ context.Context, req *webauthnpb.GetUserRequest) (*webauthnpb.GetAuthenticatorsResponse, error) {
	var user *User
	switch l := req.Lookup.(type) {
	case *webauthnpb.GetUserRequest_UserId:
		for _, usr := range u.Users {
			if usr.User.Id == l.UserId {
				user = usr
				break
			}
		}
		if user == nil {
			return nil, status.Error(codes.NotFound, "User not found")
		}
	case *webauthnpb.GetUserRequest_Username:
		usr, ok := u.Users[l.Username]
		if !ok {
			return nil, status.Error(codes.NotFound, "User not found")
		}
		user = usr
	default:
		return nil, status.Error(codes.InvalidArgument, "Bad lookup query")
	}

	return &webauthnpb.GetAuthenticatorsResponse{
		Authenticators: user.Authenticators,
	}, nil
}

// GetAuthenticator returns the authenticator matching the provided ID
func (u *UserStore) GetAuthenticator(_ context.Context, req *webauthnpb.GetAuthenticatorRequest) (*webauthnpb.GetAuthenticatorResponse, error) {
	var auth *webauthnpb.WebauthnAuthenticator
	for _, v := range u.Users {
		for _, a := range v.Authenticators {
			if bytes.Equal(a.Id, req.AuthenticatorId) {
				auth = a
			}
		}
	}
	if auth == nil {
		return nil, status.Error(codes.NotFound, "Authenticator not found")
	}

	return &webauthnpb.GetAuthenticatorResponse{
		Authenticator: auth,
	}, nil
}
