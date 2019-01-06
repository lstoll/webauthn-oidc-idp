package main

import (
	"encoding/xml"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/lstoll/idp/idppb"
	"github.com/pkg/errors"
)

type ClientProvider struct{}

func (c *ClientProvider) OIDCClient(clientID string) (client *idppb.OIDCClient, ok bool, err error) {
	if clientID == "example-app" {
		return &idppb.OIDCClient{
			Id:           "example-app",
			RedirectUris: []string{"http://localhost:5555/callback"},
			Name:         "Example app",
			Secret:       "ZXhhbXBsZS1hcHAtc2VjcmV0",
		}, true, nil
	}
	return nil, false, nil
}

func (c *ClientProvider) SAMLServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	ed := &saml.EntityDescriptor{}
	err := xml.Unmarshal([]byte(samlMetadata), ed)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshaling xml")
	}
	return ed, nil
}

// 	curl localhost:5555/saml/metadata
const samlMetadata = `
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2019-01-07T06:12:51.936Z" entityID="http://localhost:5555/saml/metadata">
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
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:5555/saml/acs" index="1"></AssertionConsumerService>
  </SPSSODescriptor>
</EntityDescriptor>`
