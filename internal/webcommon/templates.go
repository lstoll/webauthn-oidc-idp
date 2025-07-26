package webcommon

import (
	"embed"
	"html/template"
	"io"
	"log"
	"maps"

	"github.com/lstoll/web"
)

//go:embed templates/*
var templates embed.FS

// TemplateData holds the data passed to templates
type TemplateData struct {
	Title        string
	UserLoggedIn bool
	Username     string
	// Add more fields as needed for different pages
}

var Templates *template.Template

var FuncMap = template.FuncMap{
	"default": func(value, defaultValue interface{}) interface{} {
		if value == nil || value == "" {
			return defaultValue
		}
		return value
	},
}

// init parses all templates on package initialization
func init() {
	var err error

	// Create template with custom functions
	f := maps.Clone(FuncMap)
	maps.Copy(f, web.StubTemplateFuncs)
	Templates, err = template.New("").Funcs(f).ParseFS(templates, "templates/*.html.tmpl")
	if err != nil {
		log.Fatal("Failed to parse templates:", err)
	}
}

// RenderLogin renders the login page
func RenderLogin(w io.Writer, data TemplateData) error {
	return Templates.ExecuteTemplate(w, "login.html.tmpl", data)
}

// Example usage:
// func main() {
//     data := TemplateData{
//         Title:        "Login - IDP",
//         UserLoggedIn: false,
//         Username:     "",
//     }
//
//     // Render to HTTP response
//     http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
//         w.Header().Set("Content-Type", "text/html; charset=utf-8")
//         if err := RenderLogin(w, data); err != nil {
//             http.Error(w, "Internal Server Error", http.StatusInternalServerError)
//         }
//     })
//
//     log.Fatal(http.ListenAndServe(":8080", nil))
// }
