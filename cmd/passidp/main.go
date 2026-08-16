package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	promversion "github.com/prometheus/common/version"
	"golang.org/x/term"
	"lds.li/passidp/internal/admincli"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/idp"
	"lds.li/passidp/internal/policy"
)

const progname = "webauthn-oidc-idp"

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		promversion.Version = info.Main.Version
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if promversion.Revision == "" {
					promversion.Revision = setting.Value
				}
			case "vcs.modified":
				if setting.Value == "true" && promversion.Revision != "" && !strings.HasSuffix(promversion.Revision, "-modified") {
					promversion.Revision += "-modified"
				}
			case "vcs.branch":
				if promversion.Branch == "" {
					promversion.Branch = setting.Value
				}
			}
		}
	}
	prometheus.MustRegister(versioncollector.NewCollector(strings.ReplaceAll(progname, "-", "_")))
}

var rootCmd = struct {
	Debug bool `env:"DEBUG" help:"Enable debug logging"`

	Version kong.VersionFlag `help:"Print version information"`

	ConfigFile kong.NamedFileContentFlag `name:"config" required:"" env:"IDP_CONFIG_FILE" help:"Path to the config file."`
	Paths      admincli.Paths            `embed:""`

	Serve          idp.ServeCmd              `cmd:"" help:"Serve the IDP server."`
	ValidateConfig ValidateConfigCmd         `cmd:"" help:"Validate the configuration file."`
	AddCredential  admincli.AddCredentialCmd `cmd:"" help:"Add a credential to a user."`
}{}

type ValidateConfigCmd struct{}

func (c *ValidateConfigCmd) Run() error {
	slog.Info("Configuration and policies are valid")
	return nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
		<-sigCh
		os.Exit(1)
	}()

	clictx := kong.Parse(
		&rootCmd,
		kong.Description("passidp is a webauthn/oidc identity provider"),
		kong.Vars{"version": promversion.Version},
	)

	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if rootCmd.Debug {
		slogOpts.Level = slog.LevelDebug
	}
	var handler slog.Handler
	if term.IsTerminal(int(os.Stderr.Fd())) {
		handler = slog.NewTextHandler(os.Stderr, slogOpts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, slogOpts)
	}
	slog.SetDefault(slog.New(handler))

	if err := validatePaths(clictx.Selected().Name, rootCmd.Paths); err != nil {
		clictx.FatalIfErrorf(err)
	}

	cfg, err := config.ParseConfig(rootCmd.ConfigFile)
	if err != nil {
		clictx.Fatalf("parse config from %s: %v", rootCmd.ConfigFile.Filename, err)
	}

	if err := policy.ValidatePolicies(cfg); err != nil {
		clictx.Fatalf("validate policies: %v", err)
	}

	clictx.Bind(cfg)
	clictx.Bind(rootCmd.Paths)

	clictx.BindTo(ctx, (*context.Context)(nil))
	clictx.FatalIfErrorf(clictx.Run())
}

func validatePaths(command string, paths admincli.Paths) error {
	switch command {
	case "validate-config":
		return nil
	case "serve":
		if paths.CredentialStorePath == "" {
			return fmt.Errorf("credential store path is required")
		}
		if paths.StatePath == "" {
			return fmt.Errorf("state path is required")
		}
	case "add-credential":
		if paths.StatePath == "" {
			return fmt.Errorf("state path is required")
		}
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	return nil
}
