package main

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "secret")

	b, err := os.ReadFile("config.json")
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	var cfg config
	if err := loadConfig(b, &cfg); err != nil {
		t.Fatalf("load config file: %v", err)
	}

	if cfg.EncryptionKey != "secret" {
		t.Errorf("encryption key not expanded to $ENCRYPTION_KEY")
	}
}
