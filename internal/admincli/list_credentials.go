package admincli

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"lds.li/passidp/internal/admin"
	"lds.li/passidp/internal/config"
)

type ListCredentialsCmd struct {
	Output io.Writer `kong:"-"`
}

func (c *ListCredentialsCmd) Run(ctx context.Context, cfg *config.Config, paths Paths) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	credStore, err := admin.OpenCredentials(paths.CredentialStorePath)
	if err != nil {
		return err
	}

	credentials, err := admin.ListCredentials(cfg, credStore)
	if err != nil {
		return err
	}

	if len(credentials) == 0 {
		fmt.Fprintf(c.Output, "No credentials found.\n")
		return nil
	}

	w := tabwriter.NewWriter(c.Output, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tName\tUser ID\tUser Name\tUser Email\tCreated At\n")
	for _, cred := range credentials {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cred.ID,
			cred.Name,
			cred.UserID,
			cred.UserName,
			cred.UserEmail,
			cred.CreatedAt,
		)
	}
	return w.Flush()
}
