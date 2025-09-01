package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type ListUserGroupsCmd struct {
	UserID string `required:"" help:"ID of user to list groups for."`

	Output io.Writer `kong:"-"`
}

func (c *ListUserGroupsCmd) Run(ctx context.Context, db *sql.DB) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	userUUID, err := uuid.Parse(c.UserID)
	if err != nil {
		return fmt.Errorf("parse user-id: %w", err)
	}

	q := queries.New(db)

	_, err = q.GetUser(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", c.UserID, err)
	}

	memberships, err := q.GetUserGroupMemberships(ctx, c.UserID)
	if err != nil {
		return fmt.Errorf("get user group memberships: %w", err)
	}

	if len(memberships) == 0 {
		fmt.Fprintf(c.Output, "User %s is not a member of any groups.\n", c.UserID)
		return nil
	}

	fmt.Fprintf(c.Output, "User %s group memberships:\n", c.UserID)
	for _, m := range memberships {
		status := "active"
		endDate := "never"
		if m.EndDate.Valid {
			if m.EndDate.Time.Before(time.Now()) {
				status = "expired"
			}
			endDate = m.EndDate.Time.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(c.Output, "  %s (%s) - %s (from %s to %s)\n",
			m.GroupName, m.GroupID, status,
			m.StartDate.Format("2006-01-02 15:04:05"), endDate)
	}
	return nil
}
