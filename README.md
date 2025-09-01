# WebAuthn OIDC Identity Provider

**Note:** This is experimental software. It is probably not stable nor secure. Don't use it in production!

See [Issues](/../../issues) for the closest thing we have to a roadmap.

## Quick Start

### 1. Generate Development Certificates

```bash
brew install mkcert
mkcert -install
mkcert -cert-file=dev-cert.pem -key-file=dev-key.pem localhost
```

### 2. Start the Server

```bash
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  serve \
  --static-clients-file=etc/dev-clients.hujson \
  --cert-file=dev-cert.pem \
  --key-file=dev-key.pem \
  --listen-addr=localhost:8085
```

### 3. Test the Auth Flow

```bash
# Test with OIDC example RP
go run github.com/lstoll/oauth2ext/cmd/oidc-example-rp@latest

# Test with OIDC CLI
go run github.com/lstoll/oauth2ext/cmd/oidccli@latest \
  -issuer=https://localhost:8085 \
  -client-id=cli \
  info
```

## User Management

### Registering a New User

#### Step 1: Create User Account

```bash
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  enroll-user \
  --email=alice@example.com \
  --full-name="Alice Smith"
```

This will output something like:
```
User enrolled: alice@example.com (019902b1-1727-7db7-88d8-82bb63971bc2)
Enrollment URL: https://localhost:8085/registration?enrollment_token=a5a4c083-a947-4a3f-a586-e282bd13b6c2&user_id=019902b1-1727-7db7-88d8-82bb63971bc2
```

#### Step 2: Complete Registration

1. Open the registration URL in a browser
2. Follow the WebAuthn registration flow to set up a passkey
3. The user is now ready to authenticate

### List Users

```bash
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  list-users
```

Output:
```
Users:
  alice@example.com (019902b1-1727-7db7-88d8-82bb63971bc2) - Alice Smith
  bob@example.com (019902b2-1727-7db7-88d8-82bb63971bc3) - Bob Johnson
```

## Group Management

### Creating Groups

```bash
# Create an administrators group
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  create-group \
  --name="admins" \
  --description="System administrators"

# Create a developers group
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  create-group \
  --name="developers" \
  --description="Software developers"
```

### Listing Groups

```bash
# List all groups
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  list-groups

# List only active groups
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  list-groups \
  --active-only
```

Output:
```
Groups:
  admins (019902c1-1727-7db7-88d8-82bb63971bc4) - System administrators - active
  developers (019902c2-1727-7db7-88d8-82bb63971bc5) - Software developers - active
```

### Adding Users to Groups

```bash
# Add Alice to the admins group
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  add-user-to-group \
  --user-id=019902b1-1727-7db7-88d8-82bb63971bc2 \
  --group-id=019902c1-1727-7db7-88d8-82bb63971bc4

# Add Bob to the developers group
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  add-user-to-group \
  --user-id=019902b2-1727-7db7-88d8-82bb63971bc3 \
  --group-id=019902c2-1727-7db7-88d8-82bb63971bc5
```

### Viewing User Group Memberships

```bash
# List all groups for Alice
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  list-user-groups \
  --user-id=019902b1-1727-7db7-88d8-82bb63971bc2
```

Output:
```
User 019902b1-1727-7db7-88d8-82bb63971bc2 group memberships:
  admins (019902c1-1727-7db7-88d8-82bb63971bc4) - active (from 2025-09-01 02:30:00 to never)
```

### Removing Users from Groups

```bash
# Remove Alice from the admins group
go run ./cmd/webauthn-oidc-idp \
  --db-path=data/idp.db \
  --issuer=https://localhost:8085 \
  remove-user-from-group \
  --user-id=019902b1-1727-7db7-88d8-82bb63971bc2 \
  --group-id=019902c1-1727-7db7-88d8-82bb63971bc4
```

## Client Configuration with Required Groups

You can configure clients to require specific group memberships. Edit your client configuration file (e.g., `etc/dev-clients.hujson`):

```json
{
  "clients": [
    {
      "id": "admin-app",
      "secret": "admin-secret",
      "redirectURIs": ["https://admin.example.com/callback"],
      "requiredGroups": ["admins"],
      "scopes": ["openid", "profile", "email"]
    },
    {
      "id": "dev-app",
      "secret": "dev-secret",
      "redirectURIs": ["https://dev.example.com/callback"],
      "requiredGroups": ["developers"],
      "scopes": ["openid", "profile", "email"]
    },
    {
      "id": "public-app",
      "secret": "public-secret",
      "redirectURIs": ["https://public.example.com/callback"],
      "scopes": ["openid", "profile", "email"]
    }
  ]
}
```

When `requiredGroups` is specified:
- Users must be members of at least one of the required groups to access the client
- The user's active group memberships are included in the `groups` claim in ID and access tokens
- Users without required group memberships will be denied access during the OIDC flow

## OIDC Claims

The IDP includes the following claims in tokens:

- **Standard OIDC Claims**: `sub`, `iss`, `aud`, `exp`, `iat`, `email`, `name`
- **Custom Claims**:
  - `groups`: Array of group names the user is actively a member of (computed on-demand)

**Note**: Group claims are computed dynamically when tokens are generated, ensuring they always reflect the user's current group memberships. This means that if a user's group memberships change, the changes will be immediately reflected in new tokens without requiring any token refresh.

## Development

### Run E2E Tests

```bash
TEST_E2E=true go test -v ./e2e -count=1 -run TestE2E
```

### Database Migrations

The project uses SQLC for database code generation. After modifying queries in `db/queries/`, regenerate the Go code:

```bash
make sqlc
```
