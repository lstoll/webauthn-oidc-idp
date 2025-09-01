package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type ListUsersCmd struct {
	Output io.Writer `kong:"-"`
}

func (c *ListUsersCmd) Run(ctx context.Context, db *sql.DB) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	q := queries.New(db)

	users, err := q.GetUsers(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	if len(users) == 0 {
		fmt.Fprintf(c.Output, "No users found.\n")
		return nil
	}

	fmt.Fprintf(c.Output, "Users:\n")
	for _, u := range users {
		fmt.Fprintf(c.Output, "  %s (%s) - %s\n", u.Email, u.ID, u.FullName)
	}
	return nil
}
