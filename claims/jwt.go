package claims

import "lds.li/oauth2ext/oauth2as"

// IDTokenClaimsFromIDClaims maps the policy-facing protobuf claims into the
// application-owned portion of an oauth2ext ID token. oauth2ext constructs and
// validates all protocol claims itself.
func IDTokenClaimsFromIDClaims(claims *IDClaims) *oauth2as.IDTokenClaims {
	additional := map[string]any{}
	if claims.HasEmail() {
		additional["email"] = claims.GetEmail()
	}
	if claims.HasEmailVerified() {
		additional["email_verified"] = claims.GetEmailVerified()
	}
	if claims.HasPicture() {
		additional["picture"] = claims.GetPicture()
	}
	if claims.HasName() {
		additional["name"] = claims.GetName()
	}
	if len(claims.GetGroups()) > 0 {
		additional["groups"] = append([]string(nil), claims.GetGroups()...)
	}
	if claims.HasPreferredUsername() {
		additional["preferred_username"] = claims.GetPreferredUsername()
	}

	result := &oauth2as.IDTokenClaims{Additional: additional}
	if claims.HasSubject() {
		result.Subject = claims.GetSubject()
	}
	return result
}
