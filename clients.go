package main

import (
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/pardot/oidc/core"
	"gopkg.in/yaml.v2"
)

var (
	// reValidPublicRedirectUri is a fairly strict regular expression that must
	// match against the redirect URI for a 'public' client. It intentionally may
	// not match all URLs that are technically valid, but is it meant to match
	// all commonly constructed ones, without inadvertently falling victim to
	// parser bugs or parser inconsistencies (e.g.,
	// https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	reValidPublicRedirectURI = regexp.MustCompile(`\Ahttp://localhost(?::[0-9]{1,5})?(?:|/[A-Za-z0-9./_-]{0,1000})\z`)
)

type Client struct {
	ClientID      string   `json:"client_id" yaml:"client_id"`
	ClientSecrets []string `json:"client_secrets" yaml:"client_secrets"`
	RedirectURLs  []string `json:"redirect_urls" yaml:"redirect_urls"`
	Public        bool     `json:"public" yaml:"public"`
}

// staticClients is a clientsource that operates on a fixed list of clients.
type staticClients struct {
	clients []Client
}

func (s *staticClients) IsValidClientID(clientID string) (ok bool, err error) {
	for _, c := range s.clients {
		if c.ClientID == clientID {
			return true, nil
		}
	}
	return false, nil
}

func (s *staticClients) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (s *staticClients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	for _, c := range s.clients {
		if c.ClientID == clientID {
			for _, cs := range c.ClientSecrets {
				if cs == clientSecret {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (s *staticClients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	var cl Client
	var found bool
	for _, c := range s.clients {
		if c.ClientID == clientID {
			cl = c
			found = true
		}
	}
	if !found {
		return false, fmt.Errorf("invalid client")
	}
	if cl.Public && reValidPublicRedirectURI.MatchString(redirectURI) {
		return true, nil
	}

	for _, rurl := range cl.RedirectURLs {
		if rurl == redirectURI {
			return true, nil
		}
	}

	return false, nil
}

// fsClients extends the static source to load the static list from a given
// reader on each invocation
//
// TODO - consider caching at this level
type fsClients struct {
	readerFn func() (io.ReadCloser, error)
}

func (f *fsClients) load() (*staticClients, error) {
	r, err := f.readerFn()
	if err != nil {
		return nil, fmt.Errorf("getting reader: %v", err)
	}
	sc := &staticClients{}
	if err := yaml.NewDecoder(r).Decode(&sc.clients); err != nil {
		return nil, fmt.Errorf("decoding clients: %v", err)
	}
	return sc, nil
}

func (f *fsClients) IsValidClientID(clientID string) (ok bool, err error) {
	sc, err := f.load()
	if err != nil {
		return false, err
	}
	return sc.IsValidClientID(clientID)
}

func (f *fsClients) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (f *fsClients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	sc, err := f.load()
	if err != nil {
		return false, err
	}
	return sc.ValidateClientSecret(clientID, clientSecret)
}

func (f *fsClients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	sc, err := f.load()
	if err != nil {
		return false, err
	}
	return sc.ValidateClientRedirectURI(clientID, redirectURI)
}

// errSourceNotFound is returned by multiClients when no source handles the
// client.
var errSourceNotFound = errors.New("No source found for client ID")

// multiClients is a clientsource that acts on a series of underlying client
// sources. these are iterated in order, with the first client indicating a
// client ID is valid being the source responsible for said client.
type multiClients struct {
	sources []core.ClientSource
}

func (m *multiClients) IsValidClientID(clientID string) (ok bool, err error) {
	s, err := m.sourceForID(clientID)
	if err != nil {
		if err == errSourceNotFound {
			// no source just means invalid client ID here
			return false, nil
		}
		return false, err
	}
	return s.IsValidClientID(clientID)
}

func (m *multiClients) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	s, err := m.sourceForID(clientID)
	if err != nil {
		return false, err
	}
	return s.IsUnauthenticatedClient(clientID)
}

func (m *multiClients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	s, err := m.sourceForID(clientID)
	if err != nil {
		return false, err
	}
	return s.ValidateClientSecret(clientID, clientSecret)
}

func (m *multiClients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	s, err := m.sourceForID(clientID)
	if err != nil {
		return false, err
	}
	return s.ValidateClientRedirectURI(clientID, redirectURI)

}

// sourceForID finds the first source for which the client ID is valid, and
// returns it. If no source found, an error is returned
func (m *multiClients) sourceForID(clientID string) (core.ClientSource, error) {
	for _, cs := range m.sources {
		ok, err := cs.IsValidClientID(clientID)
		if err != nil {
			return nil, err
		}
		if ok {
			return cs, nil
		}
	}
	return nil, errSourceNotFound
}
