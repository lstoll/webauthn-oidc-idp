package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/scs/v2"
)

func TestGorillaSessions(t *testing.T) {
	smgr := scs.New()
	gsmgr := &gorillaSCSStore{
		sm: smgr,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/set", func(rw http.ResponseWriter, req *http.Request) {
		key := req.URL.Query().Get("key")
		if key == "" {
			t.Fatal("query with no key")
		}

		value := req.URL.Query().Get("value")
		if key == "" {
			t.Fatal("query with no value")
		}

		gsess, err := gsmgr.New(req, "tester")
		if err != nil {
			t.Fatal(err)
		}

		gsess.Values[key] = value

		t.Logf("set: %#v", gsess)

		if err := gsess.Save(req, rw); err != nil {
			t.Fatal(err)
		}
	})

	mux.HandleFunc("/get", func(rw http.ResponseWriter, req *http.Request) {
		key := req.URL.Query().Get("key")
		if key == "" {
			t.Fatal("query with no key")
		}

		gsess, err := gsmgr.New(req, "tester")
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("get: %#v", gsess)

		value, ok := gsess.Values[key]
		if !ok {
			http.Error(rw, fmt.Sprintf("key %s has no value", key), http.StatusNotFound)
			return
		}
		vstr, ok := value.(string)
		if !ok {
			http.Error(rw, fmt.Sprintf("key %s value is not a string", key), http.StatusInternalServerError)
			return
		}

		rw.Write([]byte(vstr))
	})

	svr := smgr.LoadAndSave(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/set?key=test1&value=value1", nil)

	svr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("set returned non-200: %d", rec.Code)
	}

	cookies := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/get?key=test1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	svr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("set returned non-200: %d", rec.Code)
	}

	if body, err := io.ReadAll(rec.Body); err != nil && string(body) != "value1" {
		t.Fatalf("wanted response body value1, got %s (err: %v)", string(body), err)
	}
}
