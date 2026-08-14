package admincli

// Paths locates on-disk stores.
type Paths struct {
	CredentialStorePath string `env:"IDP_CREDENTIAL_STORE_PATH" help:"Path to the credential store JSON file."`
	StatePath           string `env:"IDP_STATE_PATH" help:"Path to the SQLite state database."`
}
