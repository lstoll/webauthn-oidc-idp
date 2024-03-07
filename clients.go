package main

import (
	"fmt"
	"regexp"
)

// reValidPublicRedirectUri is a fairly strict regular expression that must
// match against the redirect URI for a Public client. It intentionally may
// not match all URLs that are technically valid, but is it meant to match
// all commonly constructed ones, without inadvertently falling victim to
// parser bugs or parser inconsistencies (e.g.,
// https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
var reValidPublicRedirectURI = regexp.MustCompile(`\Ahttp://(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?(?:|/[A-Za-z0-9./_-]{0,1000})\z`)

// staticClients is a core.ClientSource that operates on a fixed list of clients.
type staticClients struct {
	clients []clientConfig
}

func (s *staticClients) IsValidClientID(clientID string) (ok bool, err error) {
	for _, c := range s.clients {
		if c.ClientID == clientID {
			return true, nil
		}
	}
	return false, nil
}

func (s *staticClients) IsUnauthenticatedClient(_ string) (ok bool, err error) {
	return false, nil
}

func (s *staticClients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	for _, c := range s.clients {
		if c.ClientID == clientID {
			for _, cs := range c.ClientSecret {
				if cs == clientSecret {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (s *staticClients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	var cl clientConfig
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

	for _, rurl := range cl.RedirectURL {
		if rurl == redirectURI {
			return true, nil
		}
	}

	return false, nil
}
