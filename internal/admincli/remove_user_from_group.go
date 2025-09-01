package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type RemoveUserFromGroupCmd struct {
	UserID  string `required:"" help:"ID of user to remove from group."`
	GroupID string `required:"" help:"ID of group to remove user from."`

	Output io.Writer `kong:"-"`
}

func (c *RemoveUserFromGroupCmd) Run(ctx context.Context, db *sql.DB) error {
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

	err = q.RemoveUserFromGroup(ctx, c.UserID, c.GroupID)
	if err != nil {
		return fmt.Errorf("remove user from group: %w", err)
	}

	fmt.Fprintf(c.Output, "User %s removed from group %s\n", c.UserID, group.Name)
	return nil
}
