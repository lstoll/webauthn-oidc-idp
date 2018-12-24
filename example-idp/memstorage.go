package main

import "github.com/lstoll/idp"

var _ idp.Storage = (*MemStorage)(nil)

// MemStorage is a simple storage implementation
type MemStorage map[string]map[string][]byte

func (m MemStorage) Put(namespace, key string, data []byte) error {
	if _, ok := m[namespace]; !ok {
		m[namespace] = map[string][]byte{}
	}
	m[namespace][key] = data
	return nil
}

func (m MemStorage) Get(namespace, key string) ([]byte, error) {
	if _, ok := m[namespace]; !ok {
		return nil, nil
	}
	val, ok := m[namespace][key]
	if !ok {
		return nil, nil
	}
	return val, nil
}

func (m MemStorage) Delete(namespace, key string) error {
	if _, ok := m[namespace]; ok {
		if _, ok := m[namespace][key]; ok {
			delete(m[namespace], key)
		}
	}
	return nil
}
