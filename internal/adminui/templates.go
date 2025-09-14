package adminui

import (
	"context"
	"embed"
	"fmt"
	"html/template"

	"lds.li/web"
	"lds.li/web/templateutil"
	"lds.li/webauthn-oidc-idp/internal/webcommon"
)

//go:embed templates/*
var templatesFS embed.FS

var templates *template.Template

func init() {
	t, err := template.New("").Funcs(web.TemplateFuncs(context.Background(), webcommon.FuncMap)).ParseFS(templatesFS, "templates/*.tmpl.html")
	if err != nil {
		panic(fmt.Sprintf("failed to parse templates: %v", err))
	}
	if err := templateutil.Merge(t, webcommon.Templates); err != nil {
		panic(fmt.Sprintf("failed to merge templates: %v", err))
	}
	templates = t
}
