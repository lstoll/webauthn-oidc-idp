package main

import (
	"errors"

	"github.com/lstoll/idp"
)

var _ idp.Storage = (*MemStorage)(nil)

// MemStorage is a simple storage implementation
type MemStorage map[string]map[string][]byte

var errNotFound = errors.New("Not Found")

func (m MemStorage) Put(namespace, key string, data []byte) error {
	if _, ok := m[namespace]; !ok {
		m[namespace] = map[string][]byte{}
	}
	m[namespace][key] = data
	return nil
}

func (m MemStorage) Get(namespace, key string) ([]byte, error) {
	if _, ok := m[namespace]; !ok {
		return nil, errNotFound
	}
	val, ok := m[namespace][key]
	if !ok {
		return nil, errNotFound
	}
	return val, nil
}

func (m MemStorage) List(namespace string, batchFunc func(map[string][]byte) bool) error {
	batchFunc(m[namespace])
	return nil
}

func (m MemStorage) Delete(namespace, key string) error {
	if _, ok := m[namespace]; ok {
		if _, ok := m[namespace][key]; ok {
			delete(m[namespace], key)
		}
	}
	return nil
}

func (m MemStorage) ErrIsNotFound(err error) bool {
	return err == errNotFound
}
