package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrDynamicClientNotFound is returned when a dynamic client is not found.
	ErrDynamicClientNotFound = errors.New("dynamic client not found")
)

// DynamicClientStore persists dynamically registered OIDC clients in SQLite.
type DynamicClientStore struct {
	db *sql.DB
}

// DynamicClient is a dynamically registered OIDC client.
type DynamicClient struct {
	ID               string
	Active           bool
	ExpiresAt        time.Time
	CreatedAt        time.Time
	ClientSecret     string
	RegistrationBlob json.RawMessage
}

// NewDynamicClientStore returns a SQL-backed dynamic client store.
func NewDynamicClientStore(sqlDB *sql.DB) *DynamicClientStore {
	return &DynamicClientStore{db: sqlDB}
}

func (s *DynamicClientStore) GetDynamicClient(ctx context.Context, id string) (DynamicClient, error) {
	row, err := s.getDynamicClientRow(ctx, id)
	if err != nil {
		return DynamicClient{}, err
	}
	if !row.Active || time.Now().After(row.ExpiresAt) {
		return DynamicClient{}, ErrDynamicClientNotFound
	}
	return row, nil
}

func (s *DynamicClientStore) CreateDynamicClient(ctx context.Context, id, clientSecret, registrationBlob string, expiresAt time.Time) error {
	_, err := s.getDynamicClientRow(ctx, id)
	if err == nil {
		return fmt.Errorf("client %s already exists", id)
	}
	if !errors.Is(err, ErrDynamicClientNotFound) {
		return fmt.Errorf("check existing client: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO dynamic_clients (id, active, expires_at, created_at, client_secret, registration_blob)
		VALUES (?, ?, ?, ?, ?, ?)`,
		id, true, expiresAt, time.Now(), clientSecret, json.RawMessage(registrationBlob))
	return err
}

func (s *DynamicClientStore) DeactivateDynamicClient(ctx context.Context, id string) error {
	if _, err := s.getDynamicClientRow(ctx, id); err != nil {
		return err
	}

	_, err := s.db.ExecContext(ctx, `UPDATE dynamic_clients SET active = false WHERE id = ?`, id)
	return err
}

func (s *DynamicClientStore) ListActiveDynamicClients(ctx context.Context) ([]DynamicClient, error) {
	rows, err := s.db.QueryContext(ctx, dynamicClientSelect+`
		WHERE active = true AND expires_at > ?
		ORDER BY created_at DESC`, time.Now())
	if err != nil {
		return nil, fmt.Errorf("list active dynamic clients: %w", err)
	}
	defer rows.Close()

	var clients []DynamicClient
	for rows.Next() {
		row, err := scanDynamicClient(rows)
		if err != nil {
			return nil, fmt.Errorf("list active dynamic clients: %w", err)
		}
		clients = append(clients, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active dynamic clients: %w", err)
	}
	return clients, nil
}

func (s *DynamicClientStore) CleanupExpiredDynamicClients() (int, error) {
	result, err := s.db.ExecContext(context.Background(), `
		DELETE FROM dynamic_clients WHERE active = false OR expires_at < ?`, time.Now())
	if err != nil {
		return 0, fmt.Errorf("delete expired dynamic clients: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired dynamic clients: %w", err)
	}
	return int(deleted), nil
}

const dynamicClientSelect = `
	SELECT id, active, expires_at, created_at, client_secret, registration_blob
	FROM dynamic_clients`

func (s *DynamicClientStore) getDynamicClientRow(ctx context.Context, id string) (DynamicClient, error) {
	row, err := scanDynamicClient(s.db.QueryRowContext(ctx, dynamicClientSelect+`
		WHERE id = ?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DynamicClient{}, ErrDynamicClientNotFound
		}
		return DynamicClient{}, fmt.Errorf("get dynamic client: %w", err)
	}
	return row, nil
}

type dynamicClientScanner interface {
	Scan(dest ...any) error
}

func scanDynamicClient(s dynamicClientScanner) (DynamicClient, error) {
	var c DynamicClient
	err := s.Scan(
		&c.ID,
		&c.Active,
		&c.ExpiresAt,
		&c.CreatedAt,
		&c.ClientSecret,
		&c.RegistrationBlob,
	)
	return c, err
}
