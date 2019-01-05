package main

import (
	"encoding/xml"
	"html/template"
	"log"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/gorilla/schema"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
)

var _ idp.Connector = (*SimpleConnector)(nil)

var decoder = schema.NewDecoder()

// SimpleConnector is a basic user/pass connector with in-memory credentials
type SimpleConnector struct {
	Logger logrus.FieldLogger
	// Users maps user -> password
	Users map[string]string
	// Authenticator to deal with
	Authenticator idp.Authenticator
}

func (s *SimpleConnector) Initialize(auth idp.Authenticator) error {
	s.Authenticator = auth
	return nil
}

type LoginForm struct {
	AuthID   string `schema:"authid,required"`
	Username string `schema:"username,required"`
	Password string `schema:"password,required"`
}

// LoginGet is a handler for GET to /login
func (s *SimpleConnector) LoginPage(w http.ResponseWriter, r *http.Request, lr idp.LoginRequest) {
	if err := loginPage.Execute(w, map[string]interface{}{"Authid": lr.AuthID}); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

// LoginGet is a handler for POST to /login
func (s *SimpleConnector) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusInternalServerError)
		return
	}

	var lf LoginForm

	// r.PostForm is a map of our POST form values
	if err := decoder.Decode(&lf, r.PostForm); err != nil {
		s.Logger.WithError(err).Error("Failed to decode login form")
		http.Error(w, "Error decoding login form", http.StatusInternalServerError)
		return
	}

	if lf.Username == "" || lf.Password == "" || lf.AuthID == "" {
		http.Error(w, "Form fields missing", http.StatusBadRequest)
		return
	}

	pw, ok := s.Users[lf.Username]

	if !ok || pw != lf.Password {
		http.Error(w, "Invalid credentials", http.StatusForbidden)
		return
	}

	redir, err := s.Authenticator.Authenticate(lf.AuthID, idppb.Identity{UserId: lf.Username})
	if err != nil {
		http.Error(w, "Error authenticating flow", http.StatusInternalServerError)
		return
	}

	log.Printf("Redirecting to %q", redir)

	http.Redirect(w, r, redir, http.StatusSeeOther)
}

func (s *SimpleConnector) OIDCClient(clientID string) (client *idppb.OIDCClient, ok bool, err error) {
	if clientID == "example-app" {
		return &idppb.OIDCClient{
			Id:           "example-app",
			RedirectUris: []string{"http://127.0.0.1:5555/callback"},
			Name:         "Example app",
			Secret:       "ZXhhbXBsZS1hcHAtc2VjcmV0",
		}, true, nil
	}
	return nil, false, nil
}

func (s *SimpleConnector) SAMLServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	ed := &saml.EntityDescriptor{}
	err := xml.Unmarshal([]byte(samlMetadata), ed)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshaling xml")
	}
	return ed, nil
}

var loginPage = template.Must(template.New("login").Parse(`<html>
<head>
<title>Log in</title>
<head>
<body>
<form action="/login" method="POST">
<input type="hidden" name="authid" value="{{ .Authid }}">
Username: <input type="text" name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Submit">
</form>
</body>
</html>
`))

// 	curl localhost:5555/saml/metadata
const samlMetadata = `
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2019-01-07T06:12:51.936Z" entityID="http://127.0.0.1:5555/saml/metadata">
  <SPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2019-01-07T06:12:51.935795Z" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIICvDCCAaQCCQC5kC4ezo8MODANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMTkwMTA1MDQ0NzE0WhcNMjkwMTAyMDQ0NzE0WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwbsaL6+VP6AEC6kX1GOfezjnoCteDa79AtkJlehYwSIAeEJxshvbdhWmlJ4JyCZZOXR5YsU+4G1UTypkNFtt4nhRyZ3U8bTwSUDEQ/36sg2wOjX5s4tYxdmyxjfb54/cT0niKcivAb12RYEH6ijyDHIbFf5HUgTk1JVSnyOdE8T0W3lDN4KvOzLjreFPwgFTsaqOrO5d2Jlyhymx4rPXnyDpDcTkYn3XrpjhnbmMj4Dl0QVo6lP8GkhFyJftKHGP+Y0h0AxwCBbFvPhOcf1tWXuJ5+3kh5MUPukIBC2EoYG565+X+4njHDndNPVtPh3cCuIwxUarqq1BLW9yVkHv/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKUbAkRatQf9eTo/zbA34PV7t1N90+5uIyOktQRmVxXNfAF74hQP208wPVU+Z9WKIhX3pNTV22y7QZZFKuBIQ32UAKgH2cqJIdRky1LuiLw27CX3MQ8r7JYzmumLnWM9u0gxBzdjoa8GjC516uzmARVDJJLXesDduimhqvYWHItOXoYsx8HRLdYemZYhsHR2DT1OgJitdp7sNNZGAm5+Rtit7NTd1S8FPwsNMp/N5kL+bXDnkDqKdat1FoZnk8BlNLZOEiNuEE6lD+iRGkaKw+sbvqENT/83OujIvgo7xgjsWFJnDNbl3soeRsYt/KRowzSgy8pl/45xDsuDyE1m6hA=</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIICvDCCAaQCCQC5kC4ezo8MODANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMTkwMTA1MDQ0NzE0WhcNMjkwMTAyMDQ0NzE0WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwbsaL6+VP6AEC6kX1GOfezjnoCteDa79AtkJlehYwSIAeEJxshvbdhWmlJ4JyCZZOXR5YsU+4G1UTypkNFtt4nhRyZ3U8bTwSUDEQ/36sg2wOjX5s4tYxdmyxjfb54/cT0niKcivAb12RYEH6ijyDHIbFf5HUgTk1JVSnyOdE8T0W3lDN4KvOzLjreFPwgFTsaqOrO5d2Jlyhymx4rPXnyDpDcTkYn3XrpjhnbmMj4Dl0QVo6lP8GkhFyJftKHGP+Y0h0AxwCBbFvPhOcf1tWXuJ5+3kh5MUPukIBC2EoYG565+X+4njHDndNPVtPh3cCuIwxUarqq1BLW9yVkHv/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKUbAkRatQf9eTo/zbA34PV7t1N90+5uIyOktQRmVxXNfAF74hQP208wPVU+Z9WKIhX3pNTV22y7QZZFKuBIQ32UAKgH2cqJIdRky1LuiLw27CX3MQ8r7JYzmumLnWM9u0gxBzdjoa8GjC516uzmARVDJJLXesDduimhqvYWHItOXoYsx8HRLdYemZYhsHR2DT1OgJitdp7sNNZGAm5+Rtit7NTd1S8FPwsNMp/N5kL+bXDnkDqKdat1FoZnk8BlNLZOEiNuEE6lD+iRGkaKw+sbvqENT/83OujIvgo7xgjsWFJnDNbl3soeRsYt/KRowzSgy8pl/45xDsuDyE1m6hA=</X509Certificate>
        </X509Data>
      </KeyInfo>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc"></EncryptionMethod>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"></EncryptionMethod>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"></EncryptionMethod>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://127.0.0.1:5555/saml/acs" index="1"></AssertionConsumerService>
  </SPSSODescriptor>
</EntityDescriptor>`
