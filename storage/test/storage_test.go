package test

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"testing"
	"time"

	"github.com/golang-migrate/migrate"
	"github.com/golang/protobuf/ptypes"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/golang/protobuf/ptypes/empty"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "github.com/lib/pq"
	"github.com/lstoll/grpce/inproc"
	"github.com/lstoll/idp/storage"
	"github.com/lstoll/idp/storage/memory"
	"github.com/lstoll/idp/storage/sqlstore"
	"github.com/lstoll/idp/storage/storagepb"
)

var dbURL string

func init() {
	flag.StringVar(&dbURL, "dburl", "", "DB to run database tests against, tests skipped if no DB. e.g postgres://localhost/idp_test?sslmode=disable")
}

func TestStorage(t *testing.T) {
	t.Run("Memory", func(t *testing.T) {
		testImpl(t, memory.MemStorage{})
	})

	t.Run("SQL", func(t *testing.T) {
		if dbURL == "" {
			t.Skip("-dburl not specifed")
			return
		}

		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			t.Fatalf("Failed to open database %v", err)
		}
		// reset DB
		if err := sqlstore.MigrateDown(db); err != nil && errors.Cause(err) != migrate.ErrNoChange {
			t.Fatalf("Failed to down migrate DB [%+v]", err)
		}
		store, err := sqlstore.New(logrus.New(), db)
		if err != nil {
			t.Fatalf("Failed to initialize storage server [%+v]", err)
		}
		testImpl(t, store)
	})
}

func testImpl(t *testing.T, stor storagepb.StorageServer) {
	ips := inproc.New()
	storagepb.RegisterStorageServer(ips.Server, stor)
	if err := ips.Start(); err != nil {
		log.Fatal(err)
	}
	defer ips.Close()

	sc := storagepb.NewStorageClient(ips.ClientConn)
	ctx := context.Background()

	t.Run("Simple Get/Put/Delete", func(t *testing.T) {
		_, err := sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks1", Keys: []string{"key1"}})
		if err == nil || status.Code(err) != codes.NotFound {
			t.Errorf("Expected not found error, got %v", err)
		}

		mreq, err := storage.PutMutation("ks1", "key2", &empty.Empty{}, nil)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}

		if _, err := sc.Mutate(ctx, mreq); err != nil {
			t.Fatalf("Unexpected error putting record [%+v]", err)
		}

		gresp, err := sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks1", Keys: []string{"key2"}})
		if err != nil {
			t.Fatalf("Unexpected error getting item %v", err)
			panic("boo")
		}
		if gresp.Items[0].Key != "key2" {
			t.Error("Wrong item returned")
		}
		e := &empty.Empty{}
		if err := ptypes.UnmarshalAny(gresp.Items[0].Object, e); err != nil {
			t.Errorf("Error unpacking Any %v", err)
		}

		mreq = storage.DeleteMutation("ks1", "key2")

		if _, err := sc.Mutate(ctx, mreq); err != nil {
			t.Fatalf("Unexpected error deleting record [%+v]", err)
		}

		_, err = sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks1", Keys: []string{"key2"}})
		if err == nil || status.Code(err) != codes.NotFound {
			t.Errorf("Expected not found error, got %v", err)
		}
	})

	t.Run("Multikey", func(t *testing.T) {
		mreq1, err := storage.PutMutation("ks1", "key1", &empty.Empty{}, nil)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}
		mreq2, err := storage.PutMutation("ks1", "key2", &empty.Empty{}, nil)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}
		mreq := &storagepb.MutateRequest{
			Mutations: []*storagepb.Mutation{
				mreq1.Mutations[0],
				mreq2.Mutations[0],
			},
		}
		if _, err := sc.Mutate(ctx, mreq); err != nil {
			t.Fatal("Unexpected error putting records")
		}

		gresp, err := sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks1", Keys: []string{"key1", "key2"}})
		if err != nil {
			t.Fatalf("Unexpected error getting items %v", err)
		}
		if len(gresp.Items) != 2 {
			t.Error("Did not return 2 items")
		}

		gresp, err = sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks1", Keys: []string{"key1", "key2", "key3"}})
		if err == nil || status.Code(err) != codes.NotFound {
			t.Error("Expected NotFound when one item doesn't exist")
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		exp := time.Now().Add(-1 * time.Hour)
		mreq, err := storage.PutMutation("ks1", "expkey", &empty.Empty{}, &exp)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}
		if _, err := sc.Mutate(ctx, mreq); err != nil {
			t.Fatal("Unexpected error putting record")
		}

		_, err = sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks1", Keys: []string{"expkey"}})
		if err == nil || status.Code(err) != codes.NotFound {
			t.Errorf("Expected not found error, got %v", err)
		}

		exp = time.Now().Add(1 * time.Hour)
		mreq, err = storage.PutMutation("ks1", "nonexpkey", &empty.Empty{}, &exp)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}
		if _, err := sc.Mutate(ctx, mreq); err != nil {
			t.Fatal("Unexpected error putting record")
		}

		_, err = sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks1", Keys: []string{"nonexpkey"}})
		if err != nil {
			t.Errorf("Expected no error getting non-expired key, but got %v", err)
		}
	})

	t.Run("Listing", func(t *testing.T) {
		mreq1, err := storage.PutMutation("listks", "pref1key1", &empty.Empty{}, nil)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}
		mreq2, err := storage.PutMutation("listks", "pref2key2", &empty.Empty{}, nil)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}
		mreq := &storagepb.MutateRequest{
			Mutations: []*storagepb.Mutation{
				mreq1.Mutations[0],
				mreq2.Mutations[0],
			},
		}
		if _, err := sc.Mutate(ctx, mreq); err != nil {
			t.Fatal("Unexpected error putting records")
		}

		lreq := &storagepb.ListRequest{Keyspace: "listks"}
		lresp, err := sc.ListKeys(ctx, lreq)
		if err != nil {
			t.Fatalf("Unexpected error listing items %v", err)
		}
		if !sameStringSlice(lresp.Keys, []string{"pref1key1", "pref2key2"}) {
			t.Errorf("Unexpected list response %v", lresp.Keys)
		}

		lreq = &storagepb.ListRequest{Keyspace: "listks", Prefix: "pref1"}
		lresp, err = sc.ListKeys(ctx, lreq)
		if err != nil {
			t.Fatalf("Unexpected error listing items %v", err)
		}
		if !sameStringSlice(lresp.Keys, []string{"pref1key1"}) {
			t.Errorf("Unexpected list response %v", lresp.Keys)
		}
	})

	t.Run("Cross-Keyspace", func(t *testing.T) {
		mreq, err := storage.PutMutation("ks1", "key1", &empty.Empty{}, nil)
		if err != nil {
			t.Fatalf("Unexpected error creating put mutation %v", err)
		}
		if _, err := sc.Mutate(ctx, mreq); err != nil {
			t.Fatal("Unexpected error putting records")
		}

		_, err = sc.Get(ctx, &storagepb.GetRequest{Keyspace: "ks2", Keys: []string{"key1"}})
		if err == nil || status.Code(err) != codes.NotFound {
			t.Error("Expected NotFound")
		}
	})

}

func sameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	if len(diff) == 0 {
		return true
	}
	return false
}
