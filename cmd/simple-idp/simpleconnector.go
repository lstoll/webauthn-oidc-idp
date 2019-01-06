package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/gorilla/schema"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
)

var _ idp.Connector = (*SimpleConnector)(nil)

var decoder = schema.NewDecoder()

// SimpleConnector is a basic user/pass connector with in-memory credentials
type SimpleConnector struct {
	Logger logrus.FieldLogger
	// Users maps user -> password
	Users map[string]string
	// Authenticator to deal with
	Authenticator idp.Authenticator
}

func (s *SimpleConnector) Initialize(auth idp.Authenticator) error {
	s.Authenticator = auth
	return nil
}

type LoginForm struct {
	AuthID   string `schema:"authid,required"`
	Username string `schema:"username,required"`
	Password string `schema:"password,required"`
}

// LoginGet is a handler for GET to /login
func (s *SimpleConnector) LoginPage(w http.ResponseWriter, r *http.Request, lr idp.LoginRequest) {
	if err := loginPage.Execute(w, map[string]interface{}{"Authid": lr.AuthID}); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

// LoginGet is a handler for POST to /login
func (s *SimpleConnector) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusInternalServerError)
		return
	}

	var lf LoginForm

	// r.PostForm is a map of our POST form values
	if err := decoder.Decode(&lf, r.PostForm); err != nil {
		s.Logger.WithError(err).Error("Failed to decode login form")
		http.Error(w, "Error decoding login form", http.StatusInternalServerError)
		return
	}

	if lf.Username == "" || lf.Password == "" || lf.AuthID == "" {
		http.Error(w, "Form fields missing", http.StatusBadRequest)
		return
	}

	pw, ok := s.Users[lf.Username]

	if !ok || pw != lf.Password {
		http.Error(w, "Invalid credentials", http.StatusForbidden)
		return
	}

	redir, err := s.Authenticator.Authenticate(lf.AuthID, idppb.Identity{UserId: lf.Username})
	if err != nil {
		http.Error(w, "Error authenticating flow", http.StatusInternalServerError)
		return
	}

	log.Printf("Redirecting to %q", redir)

	http.Redirect(w, r, redir, http.StatusSeeOther)
}

var loginPage = template.Must(template.New("login").Parse(`<html>
<head>
<title>Log in</title>
<head>
<body>
<form action="/login" method="POST">
<input type="hidden" name="authid" value="{{ .Authid }}">
Username: <input type="text" name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Submit">
</form>
</body>
</html>
`))
