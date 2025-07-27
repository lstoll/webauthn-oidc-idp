package webcommon

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed static/*
var static embed.FS

var Static fs.FS = func() fs.FS {
	subFS, err := fs.Sub(static, "static")
	if err != nil {
		panic(fmt.Sprintf("failed to create static filesystem: %v", err))
	}
	return subFS
}()
