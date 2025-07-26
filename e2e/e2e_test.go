package e2e_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"testing"
	"time"

	"crypto/tls"
	"crypto/x509"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/clitoken"
	"github.com/lstoll/oidc/core/staticclients"
	dbpkg "github.com/lstoll/webauthn-oidc-idp/db"
	"github.com/lstoll/webauthn-oidc-idp/internal/idp"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oklog/run"
	"golang.org/x/oauth2"
)

// browserStepTimeout returns a duration to timeout browser operations. It defaults
// towards failing tests within a reasonable time, but allows an env var to
// greatly extend this when you want to interact with the browser
func browserStepTimeout() time.Duration {
	if et, _ := strconv.ParseBool(os.Getenv("TEST_E2E_EXTEND_TIMEOUT")); et {
		return 60 * time.Second
	}
	return 5 * time.Second
}

func TestE2E(t *testing.T) {
	runE2E, _ := strconv.ParseBool(os.Getenv("TEST_E2E"))
	runE2EHeadless, _ := strconv.ParseBool(os.Getenv("TEST_E2E_HEADLESS"))
	if !runE2E && !runE2EHeadless {
		t.Skip("TEST_E2E or TEST_E2E_HEADLESS not true")
	}

	/* set up a chrome instance */
	opts := chromedp.DefaultExecAllocatorOptions[:]
	if !runE2EHeadless {
		opts = append(opts, chromedp.Flag("headless", false))
	}
	if goruntime.GOOS == "linux" && os.Getenv("GITHUB_ACTIONS") != "" {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	// Add flags to ignore certificate errors for self-signed certificates
	opts = append(opts,
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("ignore-ssl-errors", true),
		chromedp.Flag("ignore-certificate-errors-spki-list", ""),
		chromedp.Flag("allow-insecure-localhost", true),
	)
	allocCtx, execCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(execCancel)

	ctx, chromeCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(t.Logf))
	t.Cleanup(chromeCancel)

	var (
		// chromeErrC gets a message when an error occurs in the browser
		// runtime, e.g js errors
		chromeErrC = make(chan error, 10000)
		// chromeDialogC gets a message when a dialog is opened. Can be handled
		// with the page.HandleJavaScriptDialog(X) action.
		chromeDialogC = make(chan struct{}, 10000)
	)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			t.Logf("*BROWSER* console.%s call:", ev.Type)
			for _, arg := range ev.Args {
				t.Logf("%s - %s\n", arg.Type, arg.Value)
			}
		case *runtime.EventExceptionThrown:
			s := ev.ExceptionDetails.Error()
			t.Logf("*BROWSER* runtime exception: %s", s)
			chromeErrC <- errors.New(s)
		case *page.EventJavascriptDialogOpening:
			t.Logf("*BROWSER* JS opened a dialog")
			chromeDialogC <- struct{}{}
		}
	})

	/* start an instance of the server */
	db := openTestDB(t)

	port := mustAllocatePort()

	issU, err := url.Parse("https://localhost:" + port)
	if err != nil {
		t.Fatal(err)
	}

	clients := []staticclients.Client{
		{
			ID:                      "test-cli",
			Secrets:                 []string{"public"},
			Public:                  true,
			PermitLocalhostRedirect: true,
		},
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	t.Cleanup(serveCancel)

	sqldb, err := sql.Open("sqlite3", "file:test.db?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open in-memory database: %v", err)
	}
	defer sqldb.Close()

	if err := dbpkg.Migrate(ctx, sqldb); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	certPath, keyPath := GenerateTestCert(t)

	// Configure http.DefaultClient to trust our test certificate
	configureDefaultClientToTrustCert(t, certPath)

	serveErr := make(chan error, 1)
	go func() {
		var (
			g    run.Group
			endC = make(chan struct{}, 1)
		)
		g.Add(func() error {
			<-endC
			return nil
		}, func(error) {
			endC <- struct{}{}
		})
		t.Cleanup(func() {
			endC <- struct{}{}
		})

		h, err := idp.NewIDP(serveCtx, &g, sqldb, db, issU, clients)
		if err != nil {
			serveErr <- err
			return
		}

		serveErr <- http.ListenAndServeTLS(net.JoinHostPort("localhost", port), certPath, keyPath, h)
	}()

	select {
	case err := <-serveErr:
		t.Fatalf("starting server: %v", err)
	case <-waitListen(ctx, net.JoinHostPort("localhost", port)):
		// continue
	case <-time.After(2 * time.Second):
		t.Fatal("server startup timed out")
	}

	provider, err := oidc.DiscoverProvider(ctx, issU.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	oa2Cfg := oauth2.Config{
		ClientID:     "test-cli",
		ClientSecret: "public",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	/* enable the virtual webauthn environment */
	var virtAuthenticatorID cdpwebauthn.AuthenticatorID

	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			ep := cdpwebauthn.Enable()
			ep.EnableUI = false // want it to be auto/headless
			if err := ep.Do(ctx); err != nil {
				return fmt.Errorf("enabling webauthn: %v", err)
			}
			ap := cdpwebauthn.AddVirtualAuthenticator(&cdpwebauthn.VirtualAuthenticatorOptions{
				Protocol:                 cdpwebauthn.AuthenticatorProtocolCtap2,
				Transport:                cdpwebauthn.AuthenticatorTransportInternal,
				HasResidentKey:           true,
				HasUserVerification:      true,
				DefaultBackupEligibility: false,
				DefaultBackupState:       false,
				// want to be headless/non-interactive
				AutomaticPresenceSimulation: true,
				IsUserVerified:              true,
			})
			aid, err := ap.Do(ctx)
			if err != nil {
				return fmt.Errorf("adding virtual authenticator: %v", err)
			}
			virtAuthenticatorID = aid
			return nil
		}),
	); err != nil {
		t.Fatalf("running webauthn enablement actions: %v", err)
	}

	_ = virtAuthenticatorID

	/* start testing */

	testOk := t.Run("Registration", func(t *testing.T) {
		// first enroll a user.
		result, err := idp.EnrollCmd(ctx, sqldb, idp.EnrollArgs{
			Email:    "test.user@example.com",
			FullName: "Test User",
			Issuer:   issU,
		})
		if err != nil {
			t.Fatalf("enrolling user: %v", err)
		}

		runErrC := make(chan error, 1)
		doneC := make(chan struct{}, 1)
		go func() {
			err := chromedp.Run(ctx,
				chromedp.Navigate(result.EnrollmentURL.String()),
				chromedp.WaitVisible(`//button[text()='Register Key']`),
				chromedp.SendKeys(`//input[@id='keyName']`, "Test Passkey"),
				chromedp.Click(`//button[text()='Register Key']`),
				// we just go back to the same page with no feedback currently lol
				chromedp.WaitVisible(`//button[text()='Register Key']`),
				// but because that's the same as the page we're registering on,
				// there's no feedback so we terminate before the request
				// finishes. So we just sleep on it.
				// TODO(lstoll) provide proper feedback that something is
				// registered, so we can wait appropriately.
				chromedp.Sleep(1*time.Second),
			)
			if err != nil {
				runErrC <- err
			}
			doneC <- struct{}{}
		}()

		select {
		case err := <-runErrC:
			t.Fatalf("running browser steps: %v", err)
		case err := <-chromeErrC:
			t.Fatalf("error in browser runtime: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("step timed out")
		case <-doneC:
		}

		_, err = queries.New(sqldb).GetUser(ctx, result.UserID)
		if err != nil {
			t.Fatal(err)
		}
		creds, err := queries.New(sqldb).GetUserCredentials(ctx, result.UserID)
		if err != nil {
			t.Fatal(err)
		}
		if len(creds) != 1 {
			t.Fatalf("expected user to have 1 credential, got: %d", len(creds))
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Successful Login", func(t *testing.T) {
		tokC, loginErrC := cliLoginFlow(ctx, t, oa2Cfg)

		runErrC := make(chan error, 1)
		doneC := make(chan struct{}, 1)
		go func() {
			err := chromedp.Run(ctx,
				chromedp.Sleep(1*time.Second),
			)
			if err != nil {
				runErrC <- err
			}
			doneC <- struct{}{}
		}()

		select {
		case tok := <-tokC:
			ui, err := provider.Userinfo(ctx, oa2Cfg.TokenSource(ctx, tok))
			if err != nil {
				t.Fatalf("getting userinfo: %v", err)
			}
			t.Logf("userinfo: %v", ui)
			// positive case
			//
			// TODO(lstoll) get userinfo
			_ = tok
		case err := <-loginErrC:
			t.Fatalf("error in CLI flow: %v", err)
		case err := <-runErrC:
			t.Fatalf("running browser steps: %v", err)
		case err := <-chromeErrC:
			t.Fatalf("error in browser runtime: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("step timed out")
		case <-doneC:
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Failed Login", func(t *testing.T) {
		// remove all credentials, test the case where it fails.
		if err := chromedp.Run(ctx,
			cdpwebauthn.ClearCredentials(virtAuthenticatorID),
		); err != nil {
			t.Fatal(err)
		}

		tokC, errC := cliLoginFlow(ctx, t, oa2Cfg)

		runErrC := make(chan error, 1)
		doneC := make(chan struct{}, 1)
		go func() {
			err := chromedp.Run(ctx,
				// sit back and let the auto-login fail
				chromedp.Sleep(5*time.Second),
			)
			if err != nil {
				runErrC <- err
			}
			doneC <- struct{}{}
		}()

		select {
		case <-chromeDialogC:
			// this is when we get an alert. currently this is how we flag errors.
			if err := chromedp.Run(ctx,
				page.HandleJavaScriptDialog(true),
			); err != nil {
				t.Fatalf("dismissing dialog: %v", err)
			}
		case bErr := <-chromeErrC:
			// this is for unhandled exceptions
			t.Logf("expected browser error returned: %v", bErr)
		case cdpErr := <-runErrC:
			t.Fatalf("chromedp error: %v", cdpErr)
		case gt := <-tokC:
			t.Fatalf("no creds should have got us no token, but got: %v", gt)
		case err := <-errC:
			t.Fatalf("error triggering CLI flow: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("timed out waiting for token")
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)
}

// cliLoginFlow starts a login flow via the oidc cli library. It will trigger
// the browser instance associated with ctx to navigate to the login page. When
// the flow completes, the resulting OIDC token will be returned on the channel.
// If an error occurs, that will be returned on that channel. It is the callers
// responsibility to complete the flow - this will only get you to the initial
// URL for the flow.
func cliLoginFlow(ctx context.Context, t *testing.T, oa2Cfg oauth2.Config) (chan *oauth2.Token, chan error) { //nolint:thelper // it's not that kind of helper
	openCh := make(chan struct{}, 1)

	cli, err := clitoken.NewSource(ctx, oa2Cfg, clitoken.WithOpener(&chromeDPOpener{notifyCh: openCh}))
	if err != nil {
		t.Fatal(err)
	}

	tokC := make(chan *oauth2.Token, 1)
	errC := make(chan error, 10)

	go func() {
		tok, err := cli.Token()
		if err != nil {
			t.Logf("getting token: %v", err)
			errC <- err
			return
		}
		tokC <- tok
	}()

	select {
	case <-openCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("browser not open for token flow within timeout")
	}

	return tokC, errC
}

// configureDefaultClientToTrustCert modifies http.DefaultClient to trust the certificate at certPath
func configureDefaultClientToTrustCert(t *testing.T, certPath string) {
	t.Helper()

	// Read the certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading certificate file: %v", err)
	}

	// Create a certificate pool and add our certificate
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certData) {
		t.Fatal("failed to append certificate to pool")
	}

	// Modify http.DefaultClient to trust our certificate
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
}

func mustAllocatePort() string {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		panic(err)
	}
	if err := l.Close(); err != nil {
		panic(err)
	}
	return port
}

func waitListen(ctx context.Context, addr string) chan struct{} {
	c := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err != nil {
				continue
			}
			c <- struct{}{}
		}
	}()
	return c
}

// logAction can be dropped into a chromedp.Run, to do some classic printf
// troubleshooting
//
//nolint:unparam // we use this on and off
func logAction(tb testing.TB, format string, args ...any) chromedp.Action { //nolint:unused // keep it, it's regularly useful
	tb.Helper()

	return chromedp.ActionFunc(func(context.Context) error {
		tb.Logf(format, args...)
		return nil
	})
}

func clearErrchan(c chan error) {
loop:
	for {
		select {
		case <-c:
		default:
			break loop
		}
	}
}

// chromeDPopener is an opener that uses chromedp. It assume the context passed
// to Open contains a chromedp handle.
type chromeDPOpener struct {
	// notifyCh will get messages sent when something is opened, if not nil
	notifyCh chan struct{}
}

// Open the URL with the chromedp instance in the given context.
func (c *chromeDPOpener) Open(ctx context.Context, url string) error {
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
	); err != nil {
		return fmt.Errorf("opening url: %v", err)
	}
	if c.notifyCh != nil {
		c.notifyCh <- struct{}{}
	}
	return nil
}

func openTestDB(t *testing.T) *idp.DB {
	t.Helper()

	db, err := idp.OpenDB(filepath.Join(t.TempDir(), "db.json"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	return db
}
