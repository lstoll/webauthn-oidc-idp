package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"text/tabwriter"
)

func newTestStorage(t *testing.T) *storage {
	t.Helper()

	s, err := newStorage(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func logTable(t *testing.T, db *sql.DB, tableName string) {
	t.Helper()

	query := fmt.Sprintf("select * from %s", tableName)

	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Query: %s", query)

	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}

	sb := &strings.Builder{}
	w := tabwriter.NewWriter(sb, 0, 2, 1, ' ', 0)

	_, _ = w.Write([]byte(strings.Join(cols, "\t") + "\n"))

	for rows.Next() {
		row := make([][]byte, len(cols))
		rowPtr := make([]any, len(cols))
		for i := range row {
			rowPtr[i] = &row[i]
		}
		if err := rows.Scan(rowPtr...); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(bytes.Join(row, []byte("\t")))
		_, _ = w.Write([]byte("\n"))
	}

	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	w.Flush()
	t.Log("\n" + sb.String())
}
