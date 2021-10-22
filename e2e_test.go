package main

import (
	"context"
	"log"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
)

func TestE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	op := runExampleOP(ctx, t)
	t.Cleanup(func() { op.Stop(t) })

	rp := runExampleRP(ctx, t)
	t.Cleanup(func() { rp.Stop(t) })

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	// create chrome instance
	ctx, cancel = chromedp.NewContext(
		allocCtx,
		chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	t.Run("Upstream OIDC provider", func(t *testing.T) {
		us := &memWebauthnUserStore{
			users: map[string]DynamoWebauthnUser{},
		}
		_ = us
	})

	// navigate to a page, wait for an element, click
	err := chromedp.Run(ctx,
		chromedp.Navigate(rp.RPAddr),
		// wait for footer element is visible (ie, page is loaded)
		chromedp.WaitVisible(`body > footer`),
		// find and click "Expand All" link
		// chromedp.Click(`#pkg-examples > div`, chromedp.NodeVisible),
		// retrieve the value of the textarea
		// chromedp.Value(`#example_After .play .input textarea`, &example),
	)
	if err != nil {
		log.Fatal(err)
	}
}

type exampleOP struct {
	Issuer string
	Output []byte
	p      *exec.Cmd
	errC   chan error
}

func runExampleOP(ctx context.Context, t *testing.T) *exampleOP {
	p, err := exec.LookPath("oidc-example-op")
	if err != nil {
		t.Fatalf("finding oidc-example-op binary: %v", err)
	}

	op := &exampleOP{
		Issuer: "http://localhost:8085",
		p:      exec.CommandContext(ctx, p),
		errC:   make(chan error),
	}

	go func() {
		o, err := op.p.CombinedOutput()
		if err != nil {
			op.errC <- err
		}
		op.Output = o
	}()

	waitListen(t, "localhost:8085")

	return op
}

func (e *exampleOP) Stop(t *testing.T) {
	select {
	case err := <-e.errC:
		t.Errorf("running example op: %v", err)
	default:
	}
	if err := e.p.Process.Kill(); err != nil {
		t.Errorf("killing example op: %v", err)
	}
}

type exampleRP struct {
	RPAddr string
	Output []byte
	p      *exec.Cmd
	errC   chan error
}

func runExampleRP(ctx context.Context, t *testing.T) *exampleRP {
	p, err := exec.LookPath("oidc-example-rp")
	if err != nil {
		t.Fatalf("finding oidc-example-rp binary: %v", err)
	}

	rp := &exampleRP{
		RPAddr: "http://localhost:8084",
		p:      exec.CommandContext(ctx, p),
		errC:   make(chan error),
	}

	go func() {
		o, err := rp.p.CombinedOutput()
		if err != nil {
			rp.errC <- err
		}
		rp.Output = o
	}()

	waitListen(t, "localhost:8084")

	return rp
}

func (e *exampleRP) Stop(t *testing.T) {
	select {
	case err := <-e.errC:
		t.Errorf("running example rp: %v", err)
	default:
	}
	if err := e.p.Process.Kill(); err != nil {
		t.Errorf("killing example rp: %v", err)
	}
}

func waitListen(t *testing.T, addr string) {
	// 1 sec
	for i := 0; i < 1000; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s after 1sec", addr)
}

type memWebauthnUserStore struct {
	users map[string]DynamoWebauthnUser
}

func (m *memWebauthnUserStore) GetUserByID(_ context.Context, id string) (*DynamoWebauthnUser, bool, error) {
	u, ok := m.users[id]
	return &u, ok, nil
}

func (m *memWebauthnUserStore) GetUserByEmail(_ context.Context, email string) (*DynamoWebauthnUser, bool, error) {
	for _, u := range m.users {
		if u.Email == email {
			return &u, true, nil
		}
	}
	return nil, false, nil
}

func (m *memWebauthnUserStore) PutUser(_ context.Context, u *DynamoWebauthnUser) (id string, err error) {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	m.users[u.ID] = *u
	return u.ID, nil
}

func (m *memWebauthnUserStore) ListUsers(_ context.Context) ([]*DynamoWebauthnUser, error) {
	var ret []*DynamoWebauthnUser
	for _, u := range m.users {
		ret = append(ret, &u)
	}
	return ret, nil
}

func (m *memWebauthnUserStore) DeleteUser(_ context.Context, id string) error {
	delete(m.users, id)
	return nil
}
