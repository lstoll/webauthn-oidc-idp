package storage

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"lds.li/keyset"
)

var (
	keysetKeyCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyset_key_count",
			Help: "Number of keys in a keyset",
		},
		[]string{"keyset_name"},
	)

	stateSQLiteFileSizeBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "state_sqlite_file_size_bytes",
			Help: "Size in bytes of the SQLite state file",
		},
	)
)

// ReportKeysetMetrics publishes Prometheus metrics for a keyset.
func ReportKeysetMetrics(public keyset.Public) {
	keysetKeyCount.WithLabelValues(public.Name).Set(float64(len(public.Keys)))
}

// ReportStateFileSize publishes the SQLite state file size metric.
func ReportStateFileSize(path string) {
	size, err := getFileSize(path)
	if err != nil {
		return
	}
	stateSQLiteFileSizeBytes.Set(float64(size))
}

func getFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
