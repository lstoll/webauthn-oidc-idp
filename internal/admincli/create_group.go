package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

type CreateGroupCmd struct {
	Name        string `required:"" help:"Name of the group."`
	Description string `help:"Description of the group."`
	Active      bool   `default:"true" help:"Whether the group is active."`

	Output io.Writer `kong:"-"`
}

func (c *CreateGroupCmd) Run(ctx context.Context, db *sql.DB) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	q := queries.New(db)

	// Check if group already exists
	_, err := q.GetGroupByName(ctx, c.Name)
	if err == nil {
		return fmt.Errorf("group with name %s already exists", c.Name)
	}

	var description sql.NullString
	if c.Description != "" {
		description = sql.NullString{String: c.Description, Valid: true}
	}

	params := queries.CreateGroupParams{
		ID:          uuid.NewString(),
		Name:        c.Name,
		Description: description,
		Active:      c.Active,
	}

	group, err := q.CreateGroup(ctx, params)
	if err != nil {
		return fmt.Errorf("create group: %w", err)
	}

	fmt.Fprintf(c.Output, "Group created: %s (%s)\n", group.Name, group.ID)
	if group.Description.Valid {
		fmt.Fprintf(c.Output, "Description: %s\n", group.Description.String)
	}
	fmt.Fprintf(c.Output, "Active: %t\n", group.Active)
	return nil
}
