package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

type AddUserToGroupCmd struct {
	UserID  string `required:"" help:"ID of user to add to group."`
	GroupID string `required:"" help:"ID of group to add user to."`

	Output io.Writer `kong:"-"`
}

func (c *AddUserToGroupCmd) Run(ctx context.Context, db *sql.DB) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	q := queries.New(db)

	// Verify user exists
	userUUID, err := uuid.Parse(c.UserID)
	if err != nil {
		return fmt.Errorf("parse user-id: %w", err)
	}

	_, err = q.GetUser(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", c.UserID, err)
	}

	// Verify group exists
	group, err := q.GetGroup(ctx, c.GroupID)
	if err != nil {
		return fmt.Errorf("get group %s: %w", c.GroupID, err)
	}

	if !group.Active {
		return fmt.Errorf("cannot add user to inactive group %s", group.Name)
	}

	params := queries.AddUserToGroupParams{
		ID:        uuid.NewString(),
		UserID:    c.UserID,
		GroupID:   c.GroupID,
		StartDate: time.Now(),
		EndDate:   sql.NullTime{Valid: false}, // No end date = infinite membership
	}

	_, err = q.AddUserToGroup(ctx, params)
	if err != nil {
		return fmt.Errorf("add user to group: %w", err)
	}

	fmt.Fprintf(c.Output, "User %s added to group %s\n", c.UserID, group.Name)
	return nil
}
