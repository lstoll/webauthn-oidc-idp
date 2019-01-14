package sqlstore

import (
	"context"
	"database/sql"

	"github.com/sirupsen/logrus"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/lstoll/idp/storage/storagepb"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ storagepb.StorageServer = (*Store)(nil)
)

type Store struct {
	DB *sql.DB

	l logrus.FieldLogger
}

func New(l logrus.FieldLogger, db *sql.DB) (*Store, error) {
	if err := migrateDB(db); err != nil {
		return nil, errors.Wrap(err, "Error migrating database")
	}
	return &Store{
		DB: db,
		l:  l,
	}, nil
}

func (s *Store) Get(ctx context.Context, req *storagepb.GetRequest) (*storagepb.GetResponse, error) {
	q, err := s.DB.PrepareContext(ctx, "SELECT key, data, expires FROM kvstore WHERE keyspace = $1 AND key = ANY($2) AND ( expires IS NULL OR expires > now() )")
	if err != nil {
		s.l.WithError(err).Error("Failed to prepare GET DB statement")
		return nil, status.Error(codes.Internal, "Failed to query DB")
	}

	rows, err := q.QueryContext(ctx, req.Keyspace, pq.Array(req.Keys))
	if err != nil {
		s.l.WithError(err).Error("Failed to execute query")
		return nil, status.Error(codes.Internal, "Failed to query DB")
	}

	var resp []*storagepb.Item

	for rows.Next() {
		var key string
		var data []byte
		var expires pq.NullTime
		if err := rows.Scan(&key, &data, &expires); err != nil {
			s.l.WithError(err).Error("Error scanning result")
			return nil, status.Error(codes.Internal, "Failed to query DB")
		}

		a := any.Any{}
		if err := proto.Unmarshal(data, &a); err != nil {
			s.l.WithError(err).WithField("keyspace", req.Keyspace).WithField("key", key).Error("Failed to unmarshal")
			return nil, status.Error(codes.Internal, "Failed to query DB")
		}

		var ts *timestamp.Timestamp
		if expires.Valid {
			t, err := ptypes.TimestampProto(expires.Time)
			if err != nil {
				s.l.WithError(err).WithField("keyspace", req.Keyspace).WithField("key", key).Error("Failed to parse time")
				return nil, status.Error(codes.Internal, "Failed to query DB")
			}
			ts = t
		}

		resp = append(resp, &storagepb.Item{
			Keyspace: req.Keyspace,
			Key:      key,
			Object:   &a,
			Expires:  ts,
		})
	}

	if len(req.Keys) != len(resp) {
		// did not get all that we were asked for, that's-a-notfound
		return nil, status.Errorf(codes.NotFound, "Not all keys found, %d requested but %d found", len(req.Keys), len(resp))
	}

	return &storagepb.GetResponse{Items: resp}, nil
}

func (s *Store) ListKeys(ctx context.Context, req *storagepb.ListRequest) (*storagepb.ListResponse, error) {
	q, err := s.DB.PrepareContext(ctx, "SELECT key FROM kvstore WHERE keyspace = $1 AND key LIKE $2 || '%' AND ( expires IS NULL OR expires > now() )")
	if err != nil {
		s.l.WithError(err).Error("Failed to prepare LIST DB statement")
		return nil, status.Error(codes.Internal, "Failed to query DB")
	}

	rows, err := q.QueryContext(ctx, req.Keyspace, req.Prefix)
	if err != nil {
		s.l.WithError(err).Error("Failed to execute query")
		return nil, status.Error(codes.Internal, "Failed to query DB")
	}

	var resp []string

	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			s.l.WithError(err).Error("Error scanning result")
			return nil, status.Error(codes.Internal, "Failed to query DB")
		}

		resp = append(resp, key)
	}

	return &storagepb.ListResponse{Keys: resp}, nil
}

func (s *Store) Mutate(ctx context.Context, req *storagepb.MutateRequest) (*empty.Empty, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		s.l.WithError(err).Error("Error starting transaction")
		return nil, status.Error(codes.Internal, "Failed to mutate DB")
	}

	updQry, err := tx.PrepareContext(ctx, `
INSERT INTO kvstore (keyspace, key, data, expires)
VALUES ($1, $2, $3, $4)
ON CONFLICT (keyspace, key)
DO UPDATE SET (data, expires) = ($3, $4)
WHERE kvstore.keyspace = $1 AND kvstore.key = $2
`)
	if err != nil {
		s.l.WithError(err).Error("Error preparing update query")
		return nil, status.Error(codes.Internal, "Failed to mutate DB")
	}

	delQry, err := tx.PrepareContext(ctx, "DELETE FROM kvstore WHERE keyspace = $1 AND key = $2")
	if err != nil {
		s.l.WithError(err).Error("Error preparing update query")
		return nil, status.Error(codes.Internal, "Failed to mutate DB")
	}

	opErr := func() error {
		for _, mut := range req.Mutations {
			switch mut := mut.Mutation.(type) {
			case *storagepb.Mutation_PutItem:
				ab, err := proto.Marshal(mut.PutItem.Object)
				if err != nil {
					return errors.Wrap(err, "Error marshaling object")
				}
				var exp pq.NullTime
				if mut.PutItem.Expires != nil {
					exp.Valid = true
					e, err := ptypes.Timestamp(mut.PutItem.Expires)
					if err != nil {
						return errors.Wrap(err, "Error in time conversion")
					}
					exp.Time = e
				}
				if _, err := updQry.ExecContext(ctx, mut.PutItem.Keyspace, mut.PutItem.Key, ab, exp); err != nil {
					return errors.Wrapf(err, "Error upserting record %s/%s", mut.PutItem.Keyspace, mut.PutItem.Key)
				}
			case *storagepb.Mutation_DeleteItem:
				if _, err := delQry.ExecContext(ctx, mut.DeleteItem.Keyspace, mut.DeleteItem.Key); err != nil {
					return errors.Wrapf(err, "Error deleting record %s/%s", mut.DeleteItem.Keyspace, mut.DeleteItem.Key)
				}
			default:
				return status.Errorf(codes.Internal, "Unknown mutation oneof %T specified", mut)
			}
		}
		return nil
	}()

	if opErr != nil {
		_ = tx.Rollback()
		s.l.WithError(opErr).Error("Error running mutator")
		return nil, status.Error(codes.Internal, "Failed to mutate DB")
	}

	if err := tx.Commit(); err != nil {
		s.l.WithError(err).Error("Error commiting transaction")
		return nil, status.Error(codes.Internal, "Failed to mutate DB")
	}

	return &empty.Empty{}, nil
}
