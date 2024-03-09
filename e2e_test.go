package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/clitoken"
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
	derivedKs, err := newDerivedKeyset("aaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("deriving keyset: %v", err)
	}

	port := mustAllocatePort()

	issU, err := url.Parse("http://localhost:" + port)
	if err != nil {
		t.Fatal(err)
	}

	issConfig := issuerConfig{
		URL: issU,
		Client: []clientConfig{
			{
				ClientID:     "test-cli",
				ClientSecret: []string{"public"},
				Public:       true,
			},
		},
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	t.Cleanup(serveCancel)

	serveErr := make(chan error, 1)
	go func() {
		if err := serve(serveCtx, db, derivedKs, issConfig, net.JoinHostPort("localhost", port)); err != nil {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		t.Fatalf("starting server: %v", err)
	case <-waitListen(ctx, net.JoinHostPort("localhost", port)):
		// continue
	case <-time.After(2 * time.Second):
		t.Fatal("server startup timed out")
	}

	// not strictly needed for the E2E tests.
	reloadDB(net.JoinHostPort("localhost", port))

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

	var user User
	testOk := t.Run("Registration", func(t *testing.T) {
		// first enroll a user.
		user, err = db.CreateUser(User{
			Email:    "test.user@example.com",
			FullName: "Test User",
		})
		if err != nil {
			t.Fatal(err)
		}
		ep := registrationURL(issConfig.URL, user)

		runErrC := make(chan error, 1)
		doneC := make(chan struct{}, 1)
		go func() {
			err := chromedp.Run(ctx,
				chromedp.Navigate(ep.String()),
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

		// we need to mark the user as active for their credentials to be
		// usable.
		if err := activateUser(db, user.ID); err != nil {
			t.Fatal(err)
		}

		user, err = db.GetActivatedUserByID(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(user.Credentials) != 1 {
			t.Fatalf("expected user to have 1 credential, got: %d", len(user.Credentials))
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Successful Login", func(t *testing.T) {
		tokC, loginErrC := cliLoginFlow(ctx, t, issConfig.URL.String())

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
			if tok.Claims.Subject != user.ID {
				t.Fatalf("want sub %s, got: %s", user.ID, tok.Claims.Subject)
			}
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

		tokC, errC := cliLoginFlow(ctx, t, issConfig.URL.String())

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
func cliLoginFlow(ctx context.Context, t *testing.T, issuer string) (chan *oidc.Token, chan error) { //nolint:thelper // it's not that kind of helper
	oidccli, err := oidc.DiscoverClient(ctx, issuer, "test-cli", "public", "") // client we added at start
	if err != nil {
		t.Fatal(err)
	}
	openCh := make(chan struct{}, 1)
	cli, err := clitoken.NewSource(oidccli, clitoken.WithOpener(&chromeDPOpener{notifyCh: openCh}))
	if err != nil {
		t.Fatal(err)
	}

	tokC := make(chan *oidc.Token, 1)
	errC := make(chan error, 10)

	go func() {
		tok, err := cli.Token(ctx)
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
