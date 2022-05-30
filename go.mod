module github.com/lstoll/idp

go 1.18

replace github.com/pardot/oidc => github.com/lstoll/oidc v0.0.0-20211017044517-5317de4b6c01

require (
	github.com/aws/aws-sdk-go v1.36.24
	github.com/google/uuid v1.3.0
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.2.1
	github.com/jszwec/s3fs v0.3.1
	github.com/lstoll/awskms v0.0.0-20200603175638-a388516467f1
	github.com/oklog/run v1.1.0
	github.com/open-policy-agent/opa v0.24.0
	github.com/pardot/oidc v0.0.0-20200518180338-f8645300dfbf
	github.com/pkg/errors v0.9.1
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/duo-labs/webauthn v0.0.0-20210727191636-9f1b88ef44cc
	github.com/gorilla/csrf v1.7.1
	github.com/joho/godotenv v1.4.0
	github.com/mattn/go-sqlite3 v1.14.13
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

require (
	github.com/OneOfOne/xxhash v1.2.7 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/cloudflare/cfssl v0.0.0-20190726000631-633726f6bcb7 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/fxamacker/cbor/v2 v2.2.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20181016184325-3113b8401b8a // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yashtewari/glob-intersection v0.0.0-20180916065949-5c77d914dd0b // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
