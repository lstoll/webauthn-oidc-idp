package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"

	"lds.li/webauthn-oidc-idp/internal/queries"
)

type ListGroupsCmd struct {
	ActiveOnly bool `default:"true" help:"Only show active groups."`

	Output io.Writer `kong:"-"`
}

func (c *ListGroupsCmd) Run(ctx context.Context, db *sql.DB) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	q := queries.New(db)

	var groups []queries.Group
	var err error

	if c.ActiveOnly {
		groups, err = q.ListActiveGroups(ctx)
	} else {
		groups, err = q.ListGroups(ctx)
	}

	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}

	if len(groups) == 0 {
		fmt.Fprintf(c.Output, "No groups found.\n")
		return nil
	}

	fmt.Fprintf(c.Output, "Groups:\n")
	for _, g := range groups {
		status := "active"
		if !g.Active {
			status = "inactive"
		}
		fmt.Fprintf(c.Output, "  %s (%s) - %s\n", g.Name, g.ID, status)
		if g.Description.Valid {
			fmt.Fprintf(c.Output, "    Description: %s\n", g.Description.String)
		}
	}
	return nil
}
