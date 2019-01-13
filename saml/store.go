package saml

import (
	"context"
	"encoding/json"

	"github.com/golang/protobuf/ptypes"

	"google.golang.org/grpc/codes"

	"github.com/lstoll/idp/storage"
	"github.com/lstoll/idp/storage/storagepb"
	"google.golang.org/grpc/status"

	"github.com/crewjam/saml/samlidp"
	"github.com/pkg/errors"
)

const samlNamespace = "saml"

type store struct {
	Storage storagepb.StorageClient
}

// Get fetches the data stored in `key` and unmarshals it into `value`.
func (s *store) Get(key string, value interface{}) error {
	resp, err := s.Storage.Get(context.TODO(), &storagepb.GetRequest{Keyspace: samlNamespace, Keys: []string{key}})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return samlidp.ErrNotFound
		}
		return errors.Wrapf(err, "Error getting saml item %q", key)
	}
	bm := storagepb.Bytes{}
	if err := ptypes.UnmarshalAny(resp.Items[0].Object, &bm); err != nil {
		return errors.Wrap(err, "Error unmarshaling any")
	}
	if err := json.Unmarshal(bm.Data, value); err != nil {
		return errors.Wrapf(err, "Error unmarshaling saml item json %q", key)
	}
	return nil
}

// Put marshals `value` and stores it in `key`.
func (s *store) Put(key string, value interface{}) error {
	ib, err := json.Marshal(value)
	if err != nil {
		return errors.Wrapf(err, "Error marshaling saml item %q", key)
	}
	bm := storagepb.Bytes{Data: ib}

	mreq, err := storage.PutMutation(samlNamespace, key, &bm, nil)
	if err != nil {
		return errors.Wrap(err, "Error builing mutation")
	}
	if _, err := s.Storage.Mutate(context.TODO(), mreq); err != nil {
		return errors.Wrapf(err, "Error storing saml item %q", key)
	}
	return nil
}

// Delete removes `key`
func (s *store) Delete(key string) error {
	dm := storage.DeleteMutation(samlNamespace, key)
	if _, err := s.Storage.Mutate(context.TODO(), dm); err != nil {
		return errors.Wrapf(err, "Error deleting saml item %q", key)
	}
	return nil
}

// List returns all the keys that start with `prefix`. The prefix is
// stripped from each returned value. So if keys are ["aa", "ab", "cd"]
// then List("a") would produce []string{"a", "b"}
func (s *store) List(prefix string) ([]string, error) {
	resp, err := s.Storage.ListKeys(context.TODO(), &storagepb.ListRequest{Keyspace: samlNamespace, Prefix: prefix})
	if err != nil {
		return nil, errors.Wrap(err, "Error calling list service")
	}
	return resp.Keys, nil
}
