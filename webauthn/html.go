// Code generated by go-bindata. (@generated) DO NOT EDIT.
// sources:
// webauthn/webauthn.js
// webauthn/webauthn.tmpl.html
package webauthn

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _webauthnWebauthnJs = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x56\x5d\x8b\xe3\x36\x14\x7d\x76\x7e\xc5\x7d\xb3\xd3\x49\xed\x6c\x29\xa5\x64\x9a\x42\x9a\x5d\xe8\x07\xed\x14\x66\x4a\x1f\x4a\x29\xb2\x74\x6d\x6b\xd6\x91\x8c\x74\x3d\xd9\xb0\xe4\xbf\x17\xd9\xf2\x57\x66\xd2\x4d\xe8\xee\xdb\xce\x83\x61\xa4\x7b\xce\x3d\xf7\x23\x07\x25\x09\x14\x44\x95\x5d\x25\x49\x2e\xa9\xa8\xd3\x98\xeb\x5d\xf2\x56\xa3\x95\xf8\x6a\x99\xec\x31\x65\x35\x15\x2a\x49\x4b\x9d\x26\x3b\x66\x09\x4d\x7f\x18\x3f\xda\x59\x92\xc0\xaf\x5a\xc8\x4c\x72\x46\x52\x2b\xbb\x72\x27\x5f\xc0\xa6\x2c\xf5\x1e\x2a\x66\xad\x54\x39\x30\x48\xb5\x38\x00\x69\x30\x98\x4b\xc7\x31\x9b\xf1\x92\x59\x0b\x7f\x62\xba\x71\x54\xf0\x7e\x16\x24\x09\xbc\x46\xae\x05\xba\x78\x66\xf1\x9b\xaf\xc1\x92\x71\x78\xa9\x48\x03\x83\x3f\xa4\xa2\x6f\x37\xc6\xb0\x43\x3c\x0b\x2c\x31\x92\x1c\xfe\x11\x0d\xe4\x87\x3a\xcb\xd0\x44\x4f\xac\xac\x71\xee\xc8\x02\x83\x54\x1b\x35\xc6\x64\x46\xef\x22\x46\x3a\xf5\x61\x0b\xe0\xb0\xfe\x1e\x78\xcc\x0b\x66\xb6\x5a\xe0\x86\xa2\xe5\x7c\x7e\x3b\x0b\x8e\xb3\x46\xcd\x1b\xd5\xaa\x51\xd0\x10\xb4\x39\x3a\x31\x13\x85\x23\x3d\xa8\xfe\x53\x4f\x4a\x9a\x45\x0a\xf7\x23\x61\x3e\x2a\x36\x28\x6a\x8e\x51\x64\x17\x90\x1e\x08\xe7\x4e\x9c\x85\x1b\xb8\x6f\x53\x38\xf9\x5b\xaf\x34\x6a\x02\x16\x10\x86\x63\xbd\xdb\x02\xf9\x5b\x0b\xfb\x02\xa9\x40\x03\x54\x20\x38\x55\xb5\x85\x36\x39\x0a\xd8\x31\xe2\x05\xda\xf1\x5d\x2e\x9f\x50\x8d\x0a\xe0\x8e\xe5\xbe\xb9\x8b\xda\x90\x49\x01\x06\xad\x13\xe6\x4e\x02\x99\x41\x64\xd0\xc6\x9e\x69\xbd\x5e\xc3\x18\x31\xc6\xdc\xba\xff\x8f\xee\x43\x85\xd1\x7b\x70\x2d\x78\x63\x8c\x36\x23\x82\x07\x7c\x47\xae\x9c\xe0\xe8\x6b\xea\xb6\x25\x12\x8c\xd8\x44\x45\x86\xc4\x8b\x28\x1c\xf6\xb3\x0d\x35\xcd\x12\x26\x96\x98\xa1\x70\x01\xef\x67\x70\xf2\xb7\x43\x2a\xb4\x58\x41\xf8\xfb\xdd\xfd\x43\xb8\x78\x76\xef\xf6\x74\x05\x3f\xdf\xdf\xfd\x16\xb7\x93\x95\xd9\xa1\xcd\xde\xe8\x6f\xbe\x31\x15\xa8\xa2\x6e\x73\xe3\x49\xc3\xbe\x5a\x2e\xe7\xa3\x20\xdf\x2c\x57\xe2\xa3\xd5\x2a\x7a\xe1\xae\x6b\x94\x8d\xab\x3a\x2d\x25\xff\x05\x0f\x6e\x21\xcb\x12\x55\x8e\xb0\x86\x21\xcf\x64\xd3\xcf\x00\x9a\xf6\x9d\xd2\xd5\x16\x4d\x2c\xc5\xa5\x64\x3e\xdc\x53\x75\x33\x1e\xee\xf1\x1d\x2f\x6b\x81\x5b\x83\x02\x15\x49\x56\xf6\xe3\x0e\x32\x6d\x20\x7a\x62\x06\x24\xac\x61\x79\x0b\x12\xbe\x83\x0f\x81\x63\x27\x9c\x8a\x5b\x90\x37\x37\x3d\x51\xf0\x21\xd4\x5f\xf2\xef\x2b\x4a\x3a\x87\xf7\x35\xb6\x8b\xe9\xbf\xa7\x3b\xfb\x7c\x64\x8a\x3d\xc9\x9c\x91\x36\x31\x1f\x95\xc1\x0d\x32\x42\x17\x33\x9e\xf2\x10\x31\x1e\xf6\x05\x3b\x9c\x49\x25\x6d\xd1\x2c\x71\x23\xf1\x74\x73\x9b\xc3\x02\x99\x40\x63\x57\x7d\xdb\xc2\x0d\xe7\x58\x51\xb8\x82\x90\x55\x55\xe9\x5d\x39\x71\xcb\xd7\x61\x82\x70\xab\x15\xa1\xa2\x2f\x1f\x0e\x15\xbe\x18\xe9\x9b\xe2\x01\x2f\xfe\x26\xba\x84\x52\xac\x60\xa8\x31\x96\xa2\xcb\x62\xd8\xfe\x27\xb1\x1a\x8d\x67\x62\x8c\x23\x48\x13\x38\x5f\x0c\x73\xaf\xb4\xb2\x38\x94\x14\x30\x22\x6c\xcc\x49\xab\xbb\xf4\x11\x39\x5d\xc4\xea\x79\xe2\x67\xe8\x3e\x55\xc0\x4b\x89\x8a\x5e\x33\x62\xae\xb8\xab\x58\xa7\xd0\xb9\x67\xec\x3a\x16\xd0\xa1\xc2\x49\x5f\xdc\x81\xef\xaa\xcf\x7f\xbc\xd8\x51\x5e\xf5\x1e\x5f\xea\x5c\xaa\x0b\xcc\xb0\x89\xfb\xec\x82\xcf\xad\x8b\xb9\x67\xc9\x59\xe3\x2a\x91\xce\x1b\xd7\x29\xf4\x12\xdb\x3a\xc5\x5c\x67\x5a\x2f\xa3\x3f\xa6\x65\xe5\x48\xff\xc7\xaf\xda\x35\xfb\x6c\x54\x1f\xdf\x4f\x7a\x8b\x72\x8d\x76\xb1\xdc\xcd\xce\x5d\x5f\xe7\x7d\xa7\xe8\x81\xd8\xca\x5c\x31\xaa\x0d\x5e\x45\xd8\xa3\x06\x22\xf7\x5a\xf8\x91\x29\x51\x5e\xc7\x34\xc0\x7a\xaa\x4f\xe3\x9e\xdd\x8b\xfe\xf8\x6f\x00\x00\x00\xff\xff\x28\x15\x11\xe5\xea\x0c\x00\x00")

func webauthnWebauthnJsBytes() ([]byte, error) {
	return bindataRead(
		_webauthnWebauthnJs,
		"webauthn/webauthn.js",
	)
}

func webauthnWebauthnJs() (*asset, error) {
	bytes, err := webauthnWebauthnJsBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "webauthn/webauthn.js", size: 3306, mode: os.FileMode(420), modTime: time.Unix(1546797832, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _webauthnWebauthnTmplHtml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xcc\x58\x4d\x8f\xdb\x36\x13\xbe\xef\xaf\x98\xf0\x3d\xac\x8d\x77\x25\x35\x68\x2e\x4d\x25\x03\x29\xda\xa0\x01\xb6\x40\x50\xa4\xc8\xb1\xa0\xc5\xb1\xc5\x0d\x45\x0a\xe4\xc8\x8e\xbb\xf0\x7f\x2f\xa8\x2f\x4b\xb6\xfc\xb5\x31\x8a\xe8\x24\xd2\xf3\xf1\xcc\x70\x9e\xe1\x58\x71\x46\xb9\x9a\xdd\xdd\xc5\x19\x72\x31\xbb\x03\x00\x88\x49\x92\xc2\xd9\x67\x9c\xf3\x92\x32\x1d\x47\xf5\xba\xfe\x4d\x49\xfd\x05\x32\x8b\x8b\x84\x45\x51\x2a\x74\x98\x97\x32\x75\x2e\x4c\x4d\x1e\xe5\xa5\x0c\x7e\x08\x7f\x0a\xdf\xbc\x8e\x52\xe7\xfc\x32\xcc\xa5\x0e\x53\xe7\x18\x58\x54\x09\x73\xb4\x51\xe8\x32\x44\x62\x40\x9b\x02\x13\x46\xf8\x95\xa2\x4a\x20\x6a\x1c\xb8\xd4\xca\x82\xc0\xd9\xf4\xb4\x87\xa7\x9d\x83\x27\xc7\x66\x71\x54\x2b\x8e\x59\x59\x37\x91\x8c\x0a\x7a\x48\xf5\xbb\x7f\xc2\x4c\x0a\x84\xe7\x6e\xdd\x3e\x42\xba\x42\xf1\xcd\x5b\xd0\x46\xe3\xcf\x83\x9f\xb7\xdd\x2a\x8e\x1a\x6b\x71\x54\x67\xf3\x2e\x9e\x1b\xb1\x69\x3c\xf9\x2d\xb4\x90\x2a\xee\x5c\xc2\x7c\x24\xbc\x28\xe6\xdc\x82\x7f\x0d\xfe\x79\xcd\x76\x28\xe2\x57\x41\x00\xef\xea\x5f\x7f\xff\xf4\xc7\x23\x2c\x0d\x3a\xc8\xd0\x22\x04\x41\x63\x2e\xaa\xed\x35\x2b\x21\x57\x20\x45\xc2\x52\xa3\x09\x35\x05\x6b\xcb\x8b\x02\x6d\xdf\xa6\x17\xe9\x39\x6f\xbc\x07\x19\xca\x65\x46\x3e\x2f\x42\xae\x8e\x8b\x7b\xc3\x5c\x6a\xb4\xc1\x42\x95\x52\xb0\xd9\xdd\x20\x09\x15\xe2\x5f\x71\xc1\x4b\x45\x40\x76\x03\x5c\x0b\xf0\x49\x87\x82\x2f\x77\xa8\x07\xd6\x3d\x5e\x65\x96\x52\xa7\xdc\x0a\xd6\x77\x66\xcd\x9a\xcd\x0e\xce\xe0\x10\x92\x0a\x72\x11\xbc\x81\xde\xc2\x2c\x16\x0e\x29\x78\x33\xa2\x3e\x66\xa2\xe0\x1a\x55\x7d\x00\xbe\x12\x83\x14\x35\x0d\xb2\x76\x60\xa0\x98\x3d\x7a\xc8\xb0\x96\x94\xc1\xc6\x94\x16\xf0\xab\x74\x24\xf5\xb2\x0a\x17\x35\xc9\x94\x93\xb1\x71\x54\x9c\xb2\xd2\x82\xa8\xca\x4d\x21\x17\x6c\x97\x8e\x47\xc3\x85\xd4\x4b\xd6\x78\x72\xc4\x2d\xa1\x78\x80\x42\x21\x77\x08\xc4\x8b\xda\xf1\xc0\x5f\x78\xda\xe1\xc2\xd8\x7c\xe7\xe1\xbd\xb1\xf9\x89\x20\x2b\x0d\xa9\x8b\x92\x7a\x2c\x65\xa0\x79\x8e\x09\x2b\x1d\x5a\xff\xd6\x03\xfc\x57\xb7\xd5\x44\xe5\xbd\x55\x15\x63\x8d\x62\x50\x28\x9e\x62\x66\x94\x40\x9b\xb0\x4e\xf6\xa4\x77\xff\xac\xb8\x2a\x31\x61\xcf\xcf\x10\xb6\x4a\xb0\xdd\x76\x8d\xe2\x28\xf0\x79\x49\x64\x74\x83\xdc\x95\xf3\x5c\x52\x07\x6c\x4e\x1a\xe6\xa4\x03\x57\xa6\x29\x3a\x07\x39\x05\x3f\x36\x79\x8e\xa3\x5a\xf1\x44\x12\x23\x1f\xd7\xc9\xda\x88\x79\x95\x15\x8b\x4b\xe9\x08\xad\x6f\x96\xac\xe9\x96\xff\x63\xb3\x3f\x9b\x6d\xf8\x82\x9b\x38\xe2\xb3\xa3\x47\xb6\xc7\xc5\x13\xdb\xcd\xd6\x21\x17\x3b\x5f\xd5\xc9\x1f\xe5\x5f\x8b\x74\x8c\x82\xe0\x8b\xf3\xbb\xe5\xe1\x11\x06\xb5\x01\x75\x24\x6a\x13\x21\xf5\x32\x0c\x43\xf8\x78\x0b\x12\xb5\x4e\x6e\xc7\xa3\x1d\xec\xa5\xd4\x57\xf1\xe8\x2c\x1f\xfa\x00\x0a\xee\xdc\xda\xf8\xa3\xae\x41\xec\xd6\x7d\x10\x1f\xbb\xdd\x31\x1c\x67\x89\xfb\x42\x9c\xd7\xf3\xb6\x3d\xda\x6f\xa3\xee\xcb\xc9\xd6\x13\xe9\xbf\x2e\x8c\xa1\xf6\x62\x86\x53\x57\xe9\xa9\x82\x1f\xd8\x6e\x2d\x0e\x66\x9b\xde\x00\xf5\xc4\x57\xbc\xde\xed\x59\x50\x48\xd0\x9d\x28\x6a\xcf\x06\x48\x60\xc1\x95\xeb\x0d\x30\x5e\xa8\xea\xe1\x07\x12\x03\x91\x35\x24\xa0\x71\x0d\x9f\x71\xfe\xce\x4f\x52\x93\x69\x4f\x40\x98\xb4\xcc\x51\x53\xb8\x44\xfa\x4d\xa1\x7f\xfd\x65\xf3\x41\x4c\x86\x34\x99\x86\x46\xd7\xa7\xea\x7d\x94\x3a\x25\x69\x34\x4c\x70\xba\x37\x6d\x61\x58\x58\x5c\xa1\xa6\x66\x9a\xf0\xae\xfa\xbf\xcb\x05\x4c\xf6\xc2\x9a\x82\x45\x2a\xad\x1e\x0a\x1e\xc6\x4e\xb6\xdc\x9b\xdd\xce\x42\x6f\xdb\xc8\x34\xac\x0e\xf0\x51\x3a\x0a\x2d\xe6\x66\x85\x93\xaa\xf3\xb0\x3d\x74\xeb\xb0\xd5\x9c\x3c\xc3\x8e\xe3\x6f\x8f\x7a\xba\x1f\x30\xff\x7e\x1a\x56\xd7\xde\x03\xec\xa8\x79\x81\x6e\x4b\xd8\x56\x1d\xb6\xd3\x83\x7a\x0e\x7d\x9f\x9b\x58\x74\x90\xcc\x46\x06\xdc\xf1\x8c\xed\x55\xcb\x37\xa7\x8e\x0b\x31\x9e\xb7\xf6\x89\x22\xf8\x64\xe5\x72\x89\xb6\x2e\x4b\x28\xac\xf1\x8c\xbf\x0e\xc2\x70\x2a\x69\x93\x92\x5c\x82\xd9\xb7\xdf\x46\xe1\x05\x3e\xab\x6b\xf4\xaa\x80\xcf\x42\x3a\x30\x79\xaa\xfc\xda\x87\x13\x61\x5e\xd0\xbb\xdd\xe5\x26\x8d\xde\x67\x92\x7f\xc6\x0a\x25\xe5\x94\x66\x13\xb4\xf6\x78\xa5\xa4\x46\x3b\xa3\x30\x44\x6b\x8d\xf5\xa2\x87\x66\x2a\x18\x0a\x2d\x4d\xee\xdf\x73\xa9\x50\x00\x99\xae\xc2\xde\xc2\x3d\xfc\x1f\xbc\xde\x65\x90\xaa\xda\x9d\x4c\xbf\xdb\xd2\xdd\xee\xed\x45\x11\xac\x33\xd4\x1d\x2c\x14\xd0\x5c\x5d\x8b\x52\xa9\xcd\x43\x7b\x40\xfd\xf1\x43\x1a\xdd\xd9\xd8\x5e\xd3\x5e\xab\x29\xd3\xb7\xd7\x54\xc9\xf4\xcb\xe9\xee\x7a\xab\xf2\xbd\x5d\xd9\xf6\x43\xed\x80\x1f\xa9\xdf\xbd\x60\xfc\x55\xd0\xbf\xbc\xc6\xef\x81\xbd\xeb\xed\x8a\x4b\x60\xf0\x6f\xec\xf2\x1b\xa0\x52\xbb\xb0\xfd\x1f\x69\x55\xe7\xfa\xb7\x45\x17\x3e\x39\x9f\x92\x33\x82\x6b\xa9\x85\xf1\x90\xea\x14\x86\xfe\xbf\x08\x24\x95\xbe\x45\x21\x2d\xa6\xf4\x37\x99\xff\xb6\x09\x54\x21\xdf\xbc\x03\x8c\x4f\x31\x63\x92\xd7\x9f\xf7\xc5\xdc\xdf\x5e\x40\xdb\xdd\x3f\xf0\x5b\x8d\x44\x67\xbb\x7d\x0f\x56\x14\xc1\x87\x05\xac\x11\x32\xbe\x42\xe0\x50\x58\x74\x88\x02\x05\xb4\xd5\xfa\x50\x7f\xb7\x91\x79\x8e\x42\x72\x42\xb5\xe9\x94\x3d\xe1\xae\xac\xe4\x57\x09\x30\xb6\x17\xd0\x05\x78\xa1\xfe\x9c\xd6\x7c\xa9\x8b\xa3\xfa\x3b\xda\x5d\x1c\x55\x9f\x2b\xff\x0d\x00\x00\xff\xff\x8f\xd0\xfb\x85\xb5\x14\x00\x00")

func webauthnWebauthnTmplHtmlBytes() ([]byte, error) {
	return bindataRead(
		_webauthnWebauthnTmplHtml,
		"webauthn/webauthn.tmpl.html",
	)
}

func webauthnWebauthnTmplHtml() (*asset, error) {
	bytes, err := webauthnWebauthnTmplHtmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "webauthn/webauthn.tmpl.html", size: 5301, mode: os.FileMode(420), modTime: time.Unix(1546797832, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"webauthn/webauthn.js":        webauthnWebauthnJs,
	"webauthn/webauthn.tmpl.html": webauthnWebauthnTmplHtml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"webauthn": &bintree{nil, map[string]*bintree{
		"webauthn.js":        &bintree{webauthnWebauthnJs, map[string]*bintree{}},
		"webauthn.tmpl.html": &bintree{webauthnWebauthnTmplHtml, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
