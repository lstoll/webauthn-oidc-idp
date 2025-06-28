package idp

import (
	"net/url"
	"strings"
)

func RegistrationURL(iss *url.URL, userID string, enrollmentKey string) *url.URL {
	u := *iss
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u2, err := u.Parse("/registration")
	if err != nil {
		panic(err)
	}
	q := u2.Query()
	q.Add("user_id", userID)
	q.Add("enrollment_token", enrollmentKey)
	u2.RawQuery = q.Encode()
	return u2
}
