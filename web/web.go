package web

import (
	"embed"
)

//go:embed public/*
var PublicFiles embed.FS

//go:embed templates/*
var Templates embed.FS
