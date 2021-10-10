package main

import (
	"fmt"
	"io"
	"regexp"

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

type fsClients struct {
	readerFn func() (io.ReadCloser, error)
}

func (f *fsClients) load() ([]Client, error) {
	r, err := f.readerFn()
	if err != nil {
		return nil, fmt.Errorf("getting reader: %v", err)
	}
	var cs []Client
	if err := yaml.NewDecoder(r).Decode(&cs); err != nil {
		return nil, fmt.Errorf("decoding clients: %v", err)
	}
	return cs, nil
}

func (f *fsClients) IsValidClientID(clientID string) (ok bool, err error) {
	cs, err := f.load()
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.ClientID == clientID {
			return true, nil
		}
	}
	return false, nil
}

func (f *fsClients) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (f *fsClients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	cs, err := f.load()
	if err != nil {
		return false, err
	}

	for _, c := range cs {
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

func (f *fsClients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	cs, err := f.load()
	if err != nil {
		return false, err
	}

	var cl Client
	var found bool
	for _, c := range cs {
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
