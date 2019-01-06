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

	info := bindataFileInfo{name: "webauthn/webauthn.js", size: 3306, mode: os.FileMode(420), modTime: time.Unix(1546748549, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _webauthnWebauthnTmplHtml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xcc\x58\x4b\x8f\xdb\x36\x10\xbe\xef\xaf\x98\xb0\x87\xb5\xd1\x48\x6c\xd0\x5c\x9a\xc8\x06\x52\xa4\x41\x03\x6c\x91\x20\x48\x10\xf4\x54\xd0\xe2\xd8\xe2\x86\x22\x05\x72\x64\xc7\x5d\xec\x7f\x2f\xa8\xb7\x2c\x3f\x76\xd3\xa2\xad\x4e\x12\x3d\x8f\x6f\x66\xf8\x7d\xa2\x95\x64\x94\xeb\xe5\xd5\x55\x92\xa1\x90\xcb\x2b\x00\x80\x84\x14\x69\x5c\x7e\xc6\x95\x28\x29\x33\x09\xaf\x9f\xeb\xdf\xb4\x32\x5f\x20\x73\xb8\x5e\x30\xce\x53\x69\xe2\xbc\x54\xa9\xf7\x71\x6a\x73\x9e\x97\x2a\xfa\x21\xfe\x29\x7e\xfe\x8c\xa7\xde\x87\xc7\x38\x57\x26\x4e\xbd\x67\xe0\x50\x2f\x98\xa7\xbd\x46\x9f\x21\x12\x03\xda\x17\xb8\x60\x84\x5f\x89\x57\x06\xbc\x49\xe0\x53\xa7\x0a\x02\xef\xd2\xf3\x19\x6e\xfb\x04\xb7\x9e\x2d\x13\x5e\x3b\x1e\x8b\xb2\x6b\x2a\x39\x6a\x18\x20\xd5\xf7\xe1\x8a\x33\x25\x11\xee\xba\xe7\xf6\x92\xca\x17\x5a\xec\x5f\x80\xb1\x06\x5f\x8e\x7e\xbe\xef\x9e\x12\xde\x44\x4b\x78\xdd\xcd\xab\x64\x65\xe5\xbe\xc9\x14\x96\xd0\x41\xaa\x85\xf7\x0b\x16\x2a\x11\x45\xb1\x12\x0e\xc2\x6d\xf4\xe7\x33\xd6\xa3\x48\x9e\x44\x11\xbc\xaa\x7f\xfd\xf5\xe3\x6f\x37\xb0\xb1\xe8\x21\x43\x87\x10\x45\x4d\x38\x5e\xc7\x6b\x9e\xa4\xda\x82\x92\x0b\x96\x5a\x43\x68\x28\xda\x39\x51\x14\xe8\x86\x31\x83\xc9\x20\x79\x93\x3d\xca\x50\x6d\x32\x0a\x7d\x91\x6a\x7b\xda\x3c\x04\x16\xca\xa0\x8b\xd6\xba\x54\x92\x2d\xaf\x46\x4d\xa8\x10\xbf\xc6\xb5\x28\x35\x01\xb9\x3d\x08\x23\x21\x34\x1d\x0a\xb1\xe9\x51\x8f\xa2\x07\xbc\xda\x6e\x94\x49\x85\x93\x6c\x98\xcc\xd9\x1d\x5b\x4e\x66\x30\x85\xa4\xa3\x5c\x46\xcf\x61\xf0\x60\xd7\x6b\x8f\x14\x3d\x3f\xe2\x7e\x2c\x44\x21\x0c\xea\x7a\x00\x61\x27\x46\x29\x1a\x1a\x75\x6d\x12\xa0\x58\xde\x04\xc8\xb0\x53\x94\xc1\xde\x96\x0e\xf0\xab\xf2\xa4\xcc\xa6\x2a\x17\x0d\xa9\x54\x90\x75\x09\x2f\xce\x44\x59\x5b\x97\x57\xf5\x3b\xdc\x28\x4f\xe8\xde\x58\x97\x9f\x49\x5b\x39\x29\x53\x94\x34\xe0\x0d\x03\x23\x72\x5c\xb0\xd2\xa3\x0b\x77\xac\xef\xe8\xa7\x6e\xa9\x29\x36\x24\xac\x66\xe8\xac\x66\x50\x68\x91\x62\x66\xb5\x44\xb7\x60\x9d\xed\xd9\xec\xe1\xda\x0a\x5d\xe2\x82\xdd\xdd\x41\xdc\x3a\xc1\xfd\x7d\x47\xdd\x93\xc0\x57\x25\x91\x35\x0d\x72\x5f\xae\x72\x45\x1d\xb0\x15\x19\x58\x91\x89\x7c\x99\xa6\xe8\x3d\xe4\x14\xfd\xc8\xea\x1e\x27\xbc\x76\x3c\xd3\x47\x1e\xea\x3a\x3b\xad\x44\x8c\xfa\x1c\xe4\x8b\x35\xfa\xf5\x1d\x5b\x7e\x68\x96\xe1\x0b\xee\x13\x2e\x96\x27\xa7\x76\xc0\x8e\x33\xcb\xcd\xd2\x94\x1d\x5d\xae\x6a\xf8\x27\x19\xd1\x22\x3d\x46\x0a\x08\xea\xf4\xbf\x65\x46\xeb\x5e\x49\xa8\x46\x21\xd9\xa8\xa0\x1b\x2b\xa4\x32\x9b\xbe\xe9\xca\x6c\xe2\x38\x86\xf7\x1a\x85\x47\x20\x51\xd4\x7c\x1a\xd1\x28\xfe\xcf\x78\xd4\xc3\xde\x28\xf3\x28\x1e\x5d\xe4\xc3\x10\x40\x21\xbc\xdf\xd9\x30\xea\x1a\x44\xff\x3c\x04\xf1\xbe\x5b\x3d\x86\xe3\x22\x71\xbf\x11\xe7\xe3\x79\xdb\x8e\xf6\xef\x51\xf7\xdb\xc9\x36\x30\x19\xde\xae\xad\xa5\xf6\x55\x09\xe7\x5e\x6e\xe7\x36\xfc\x28\x76\x1b\x71\x74\xda\x18\x1c\x69\x6e\xc5\x56\xd4\xab\x83\x08\x1a\x09\xba\x89\xa2\x09\x6c\x80\x05\xac\x85\xf6\x83\x23\x45\x30\xaa\x34\x7c\x62\x31\x32\xd9\xc1\x02\x0c\xee\xe0\x33\xae\x5e\x85\xb3\xcd\x6c\x3e\x30\x90\x36\x2d\x73\x34\x14\x6f\x90\x7e\xd1\x18\x6e\x7f\xde\xbf\x95\xb3\x31\x4d\xe6\xb1\x35\xf5\x54\x43\x8e\xd2\xa4\xa4\xac\x81\x19\xce\x0f\xce\x3f\x18\x17\x0e\xb7\x68\xa8\x79\xbf\x87\x54\xc3\xdf\xd5\x1a\x66\x07\x65\xcd\xc1\x21\x95\xce\x8c\x0d\xa7\xb5\x93\x2b\x0f\x4e\x53\x17\xa1\xb7\x32\x32\x8f\xab\x01\xde\x28\x4f\xb1\xc3\xdc\x6e\x71\x56\x29\x0f\x3b\x40\xb7\x8b\x5b\xcf\xd9\x1d\xf4\x1c\x7f\x71\x32\xd3\xf5\x88\xf9\xd7\xf3\xb8\x7a\xed\x3d\x85\x9e\x9a\x0f\xf0\x6d\x09\xdb\xba\xc3\xfd\x7c\xb2\x9f\xe3\xa0\x73\x33\x87\x1e\x16\x4b\x10\x1a\x1d\xcd\xae\x3f\x66\xca\x8f\x15\x10\x32\xe1\x61\x85\x68\xba\xf6\xa1\xbc\x9e\x1f\x89\x96\x0a\x4a\xb3\x19\x3a\x17\xc2\x4d\x4f\xb0\xe1\x4a\xad\xf1\x56\x63\x8c\xce\x59\x17\x4c\xa7\x61\xc2\xd5\x60\x79\x23\x94\x46\x09\x64\xbb\xcc\x2f\xe0\x1a\xbe\x87\xe0\xf7\x72\xe2\x78\xb2\xc0\xd9\xfc\x34\xa0\x8b\x6c\x18\x5e\xdf\xb4\x35\x84\x94\xc7\xf7\x45\x8d\x79\xbc\xc6\x39\xec\xb2\x51\xa7\xa1\xd1\xb7\x75\xa9\xf5\xfe\x29\x08\x22\xcc\x0b\x1a\x4e\x48\x59\xd3\xc5\xb8\x7f\x0c\x07\xab\xa3\x48\xe0\x60\xaa\x55\xfa\xe5\x3c\x05\x4f\x06\xeb\xcf\xcf\x0f\x2a\xfa\x22\xa8\x49\xa8\x53\xd4\x1a\x96\xda\x01\x6f\xda\xf3\x6a\xd4\x9d\xd9\x61\x31\x41\x2f\x86\x0a\x77\x5c\x2c\x0e\x34\x70\xaa\x14\x9c\x5f\x68\xcb\xe3\x95\xa2\x72\x7b\xa0\x4c\x1c\x1c\xb4\x1f\xca\x73\x87\x3e\xbe\xf5\xa1\x2b\x0f\x13\x84\xdf\x6d\x09\x99\xd8\x62\x2d\x01\xda\x6e\x36\x28\x41\x99\xc0\xca\xc0\xc5\x10\x2e\xe4\xff\x97\x05\xa1\xaa\xfd\x1f\x57\x83\xe3\xaf\xbd\x63\x96\x8f\x1f\xfc\x05\x1d\x78\xc8\x2c\xd8\x67\x5b\x6a\x09\x0e\xa5\x72\x98\x52\xe8\x03\x6b\x46\xd0\xae\xfd\x41\x76\x3e\xd5\x94\x8f\xef\x5e\xbf\x03\xca\x10\xd6\xca\x08\x0d\x9e\xb0\x08\x7f\x02\x80\x82\xd8\x1b\x44\xe9\x43\xac\x15\x76\xa1\x43\xfd\x64\x2b\x97\x9a\x1a\x28\xe1\xd3\x87\x9b\xb8\x67\x5f\x4f\x3e\xce\xe1\xed\x1a\x76\x58\xef\x12\x01\x85\x43\x8f\x28\x51\x42\xbb\x89\x9f\xd6\x7f\xc4\x55\x9e\xa3\x54\x82\x50\xef\x07\xce\x81\x8c\x8f\xdc\xe2\x4f\x16\xc0\xd8\x90\xd4\x9c\x57\x9b\xe4\x38\xf9\x5f\x0e\xcc\xfa\x4f\x25\x67\x8d\xfb\x4f\x34\x09\xaf\x3f\xa0\x5c\x25\xbc\xfa\x4e\xf5\x57\x00\x00\x00\xff\xff\xb8\x92\xac\x9d\xae\x12\x00\x00")

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

	info := bindataFileInfo{name: "webauthn/webauthn.tmpl.html", size: 4782, mode: os.FileMode(420), modTime: time.Unix(1546789998, 0)}
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
