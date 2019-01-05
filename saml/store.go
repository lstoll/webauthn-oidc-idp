package saml

import (
	"encoding/json"

	"github.com/crewjam/saml/samlidp"
	"github.com/lstoll/idp"
	"github.com/pkg/errors"
)

const samlNamespace = "saml"

type store struct {
	Storage idp.Storage
}

// Get fetches the data stored in `key` and unmarshals it into `value`.
func (s *store) Get(key string, value interface{}) error {
	ib, err := s.Storage.Get(samlNamespace, key)
	if err != nil {
		if s.Storage.ErrIsNotFound(err) {
			return samlidp.ErrNotFound
		}
		return errors.Wrapf(err, "Error getting saml item %q", key)
	}
	if err := json.Unmarshal(ib, value); err != nil {
		return errors.Wrapf(err, "Error unmarshaling saml item %q", key)
	}
	return nil
}

// Put marshals `value` and stores it in `key`.
func (s *store) Put(key string, value interface{}) error {
	ib, err := json.Marshal(value)
	if err != nil {
		return errors.Wrapf(err, "Error marshaling saml item %q", key)
	}
	if err := s.Storage.Put(samlNamespace, key, ib); err != nil {
		return errors.Wrapf(err, "Error storing saml item %q", key)
	}
	return nil
}

// Delete removes `key`
func (s *store) Delete(key string) error {
	if err := s.Storage.Delete(samlNamespace, key); err != nil {
		return errors.Wrapf(err, "Error deleting saml item %q", key)
	}
	return nil
}

// List returns all the keys that start with `prefix`. The prefix is
// stripped from each returned value. So if keys are ["aa", "ab", "cd"]
// then List("a") would produce []string{"a", "b"}
func (s *store) List(prefix string) ([]string, error) {
	var ret []string
	err := s.Storage.List(samlNamespace, func(items map[string][]byte) bool {
		for k := range items {
			ret = append(ret, k)
		}
		return true
	})
	if err != nil {
		return nil, errors.Wrap(err, "Error listing items")
	}
	return ret, nil
}
