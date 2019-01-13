package memory

import (
	"context"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/timestamp"

	"github.com/golang/protobuf/ptypes"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/lstoll/idp/storage/storagepb"
)

var (
	_ storagepb.StorageServer = (*MemStorage)(nil)
)

type storeItem struct {
	Data    []byte
	Expires *time.Time
}

// MemStorage is a simple storage implementation
type MemStorage map[string]map[string]storeItem

func (m MemStorage) Get(_ context.Context, req *storagepb.GetRequest) (*storagepb.GetResponse, error) {
	if _, ok := m[req.Keyspace]; !ok {
		return nil, status.Errorf(codes.NotFound, "Keyspace %s not found", req.Keyspace)
	}
	ret := &storagepb.GetResponse{}
	for _, k := range req.Keys {
		b, ok := m[req.Keyspace][k]
		if !ok {
			return nil, status.Errorf(codes.NotFound, "Key %s not found in keyspace %s not found", k, req.Keyspace)
		}
		if b.Expires != nil && b.Expires.Before(time.Now()) {
			return nil, status.Errorf(codes.NotFound, "Key %s in keyspace %s expired", k, req.Keyspace)
		}
		var a any.Any
		if err := proto.Unmarshal(b.Data, &a); err != nil {
			return nil, status.Errorf(codes.Internal, "Failed to unmarshal object %s/%s", req.Keyspace, k)
		}
		var pexp *timestamp.Timestamp
		if b.Expires != nil {
			pexp, _ = ptypes.TimestampProto(*b.Expires)
		}
		ret.Items = append(ret.Items, &storagepb.Item{
			Keyspace: req.Keyspace,
			Key:      k,
			Object:   &a,
			Expires:  pexp,
		})
	}
	return ret, nil
}

func (m MemStorage) ListKeys(_ context.Context, req *storagepb.ListRequest) (*storagepb.ListResponse, error) {
	var lr storagepb.ListResponse
	if _, ok := m[req.Keyspace]; !ok {
		return &lr, nil
	}
	for k := range m[req.Keyspace] {
		if strings.HasPrefix(k, req.Prefix) {
			lr.Keys = append(lr.Keys, k)
		}
	}
	return &lr, nil
}

func (m MemStorage) Mutate(_ context.Context, req *storagepb.MutateRequest) (*empty.Empty, error) {
	for _, mut := range req.Mutations {
		switch mut := mut.Mutation.(type) {
		case *storagepb.Mutation_PutItem:
			ab, err := proto.Marshal(mut.PutItem.Object)
			if err != nil {
				return nil, status.Error(codes.Internal, "Error marshaling object")
			}
			var exp *time.Time
			if mut.PutItem.Expires != nil {
				e, err := ptypes.Timestamp(mut.PutItem.Expires)
				if err != nil {
					panic(err)
				}
				exp = &e
			}
			if _, ok := m[mut.PutItem.Keyspace]; !ok {
				m[mut.PutItem.Keyspace] = map[string]storeItem{}
			}
			m[mut.PutItem.Keyspace][mut.PutItem.Key] = storeItem{Data: ab, Expires: exp}
		case *storagepb.Mutation_DeleteItem:
			if _, ok := m[mut.DeleteItem.Keyspace]; !ok {
				continue
			}
			delete(m[mut.DeleteItem.Keyspace], mut.DeleteItem.Key)
		default:
			return nil, status.Errorf(codes.Internal, "Unknown mutation oneof %T specified", mut)
		}
	}
	return &empty.Empty{}, nil
}
