package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	// DefaultHTTPGetAddress Default Address
	DefaultHTTPGetAddress = "https://checkip.amazonaws.com"

	// ErrNoIP No IP found in response
	ErrNoIP = errors.New("No IP in HTTP response")

	// ErrNon200Response non 200 status code in response
	ErrNon200Response = errors.New("Non 200 Response found")
)

type globalCfg struct {
	storage *storage
	keyset  *derivedKeyset
}

func main() {
	ctx := context.Background()
	l := logrus.New()

	// this is optional, ignore when it doesn't exist
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		l.WithError(err).Fatal("Error loading .env file")
	}

	kingpin.Version(getVersion())

	app := kingpin.New("idp", "A webauthn IDP.")
	dbPath := app.Flag("db-path", "Path to database file").Envar("DB_PATH").Default("db/idp.db").String()
	securePassphrase := app.Flag("secure-passphrase", "Passphrase for DB encryption").Envar("SECURE_PASSPHRASE").Required().String()
	prevSecurePassphrases := app.Flag("prev-secure-passphrases", "Passphrase(s) previously used for DB encryption, to decrypt").Envar("SECURE_PASSPHRASES_PREV").Strings()

	serveCmd, serveRun := serveCommand(app)

	cmdName := kingpin.MustParse(app.Parse(os.Args[1:]))

	// common initialization
	ks, err := newDerivedKeyset(*securePassphrase, *prevSecurePassphrases...)
	if err != nil {
		l.WithError(err).Fatal("failed deriving keyset")
	}

	st, err := newStorage(ctx, l, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", *dbPath))
	if err != nil {
		l.WithError(err).Fatal("failed to create storage")
	}

	gcfg := &globalCfg{
		keyset:  ks,
		storage: st,
	}
	_ = gcfg

	var runErr error
	switch cmdName {
	// Register user
	case serveCmd.FullCommand():
		runErr = serveRun(ctx, gcfg)
	default:
		panic("should not happen, kingpin should handle this")
	}
	if runErr != nil {
		l.WithError(runErr).Fatal()
	}
}

func mustDecodeKey(s string) *rsa.PrivateKey {
	var r *rsa.PrivateKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatalf("un-base64 key: %v", err)
	}
	buf := bytes.Buffer{}
	buf.Write(b)
	if err := gob.NewDecoder(&buf).Decode(&r); err != nil {
		log.Fatalf("decoding key: %v", err)
	}
	return r
}

var localDevKey = mustDecodeKey("S/+BAwEBClByaXZhdGVLZXkB/4IAAQQBCVB1YmxpY0tleQH/hAABAUQB/4YAAQZQcmltZXMB/4gAAQtQcmVjb21wdXRlZAH/igAAACT/gwMBAQlQdWJsaWNLZXkB/4QAAQIBAU4B/4YAAQFFAQQAAAAK/4UFAQL/kAAAABn/hwIBAQpbXSpiaWcuSW50Af+IAAH/hgAASP+JAwEBEVByZWNvbXB1dGVkVmFsdWVzAf+KAAEEAQJEcAH/hgABAkRxAf+GAAEEUWludgH/hgABCUNSVFZhbHVlcwH/jgAAAB3/jQIBAQ5bXXJzYS5DUlRWYWx1ZQH/jgAB/4wAADH/iwMBAQhDUlRWYWx1ZQH/jAABAwEDRXhwAf+GAAEFQ29lZmYB/4YAAQFSAf+GAAAA/gFB/4IBAUEC6ucB8ZXiGQZmcUaBfbEOGfYZoPcs32XGIgHCugePcP3G7cIc5DxofX0gV5lo11+DLDFVYmVDTq+YNYrPcr6LHQH9AgACAAFBAkChrvc5tiwMhsNEEvzyal7aR9LyL3aIGivhMCLfUahUpBlsA0C4DkqqcOTzKZI1dDIibFOTgEncrRPzDWikCkEBAiEC+8WMHSJDcR+Mw/I/bsslFBjMZYkJ7j8ph8MrBmqtfp8hAu7Y7vKhGiT8Xek9Foifb7k/I/5NNOOFr4jUDCyVyejDAQEhAucjVxywBgZmlo6VaVLHwQSQN6XHh4xoBDKVJHzBlwG1ASEC0NeuV0i2a5CfLMnVYjDGp9ulxT4M+MRz79g5rOJsYbEBIQIR0UGs8sDAlPOVpuFq3dFa0PROE4YBEQuqe4Rdb+UwpgAA")

func getEnvOrDefaultStr(key, dfault string) string {
	r := os.Getenv(key)
	if r == "" {
		return dfault
	}
	return r
}

func getEnvOrDefaultBool(key string, dfault bool) bool {
	r := os.Getenv(key)
	if r == "" {
		return dfault
	}
	v, err := strconv.ParseBool(r)
	if err != nil {
		return false
	}
	return v
}

func getVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		panic("couldn't read runtime build info")
	}

	var (
		rev   string
		dirty bool
	)
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}

	verStr := bi.Main.Version + " (rev: " + rev
	if dirty {
		verStr += ", dirty"
	}
	verStr += ")"

	return verStr
}
