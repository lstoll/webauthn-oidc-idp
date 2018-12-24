package oidcserver

import (
	"html/template"
	"io"
	"net/http"
)

// TODO - one day we might want a better way to pass these in, for now this is a good simple hack

func writeOob(w io.Writer, code string) error {
	return oobTmpl.ExecuteTemplate(w, "oob", struct{ Code string }{code})
}

var oobTmpl = template.Must(template.New("oob").Parse(`<html>
<body>
<div class="theme-panel">
  <h2 class="theme-heading">Login Successful</h2>
  <p>Please copy this code, switch to your application and paste it there:</p>
  <input type="text" class="theme-form-input" value="{{ .Code }}" />
</div>
</body>
</html>`))

func writeError(w http.ResponseWriter, errCode int, errMsg string) error {
	w.WriteHeader(errCode)
	return errTmpl.ExecuteTemplate(w, "oob", struct {
		ErrType string
		ErrMsg  string
	}{
		http.StatusText(errCode),
		errMsg,
	})
}

var errTmpl = template.Must(template.New("oob").Parse(`<html>
<body>
<div class="theme-panel">
  <h2 class="theme-heading">{{ .ErrType }}</h2>
  <p>{{ .ErrMsg }}</p>
</div>
</body>
</html>`))
