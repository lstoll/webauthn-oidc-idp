package storage

import (
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/lstoll/idp/storage/storagepb"
	"github.com/pkg/errors"
)

// PutMutation builds a storage mutation for a simple put. Expires is optional
func PutMutation(keyspace, key string, object proto.Message, expires *time.Time) (*storagepb.MutateRequest, error) {
	var exp *timestamp.Timestamp
	if expires != nil {
		e, err := ptypes.TimestampProto(*expires)
		if err != nil {
			return nil, errors.Wrap(err, "Error converting time to Timestamp")
		}
		exp = e
	}
	oa, err := ptypes.MarshalAny(object)
	if err != nil {
		return nil, errors.Wrap(err, "Error marshaling proto.Message")
	}
	return &storagepb.MutateRequest{
		Mutations: []*storagepb.Mutation{
			{
				Mutation: &storagepb.Mutation_PutItem{
					PutItem: &storagepb.Item{
						Keyspace: keyspace,
						Key:      key,
						Object:   oa,
						Expires:  exp,
					},
				},
			},
		},
	}, nil
}

// DeleteMutation builds a storage mutation for a simple delete.
func DeleteMutation(keyspace, key string) *storagepb.MutateRequest {
	return &storagepb.MutateRequest{
		Mutations: []*storagepb.Mutation{
			{
				Mutation: &storagepb.Mutation_DeleteItem{
					DeleteItem: &storagepb.DeleteItem{
						Keyspace: keyspace,
						Key:      key,
					},
				},
			},
		},
	}
}
