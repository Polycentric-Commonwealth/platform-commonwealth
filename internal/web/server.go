// Package web serves the Commonwealth platform's web interface: public
// pages for everyone and a workspace for officials of the members office,
// the Commons Fund and the Audit Office. It also mounts the protocol
// endpoints other instances use.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/polycentric-commonwealth/foundation/audit"
	"github.com/polycentric-commonwealth/foundation/dividend"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
	"github.com/polycentric-commonwealth/foundation/uniqueness"

	"github.com/polycentric-commonwealth/platform-commonwealth/internal/commonwealth"
	"github.com/polycentric-commonwealth/platform-commonwealth/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	sessionCookie = "pcc_session"
	sessionLength = 8 * time.Hour
)

// Server is the Commonwealth platform's web server.
type Server struct {
	CW    *commonwealth.Commonwealth
	Store *store.Store

	// SecureCookies sets the Secure flag on session cookies; turn it off
	// only for local development over plain HTTP.
	SecureCookies bool

	secret  []byte
	pages   map[string]*template.Template
	handler http.Handler
}

// New returns a server ready to handle requests. Officials sign in with
// their own accounts in db.
func New(cw *commonwealth.Commonwealth, db *store.Store, secureCookies bool) (*Server, error) {
	s := &Server{CW: cw, Store: db, SecureCookies: secureCookies}
	var err error
	if s.secret, err = db.Secret("web-form-secret", 32); err != nil {
		return nil, err
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheFor(time.Hour, http.FileServer(http.FS(static)))))

	mux.HandleFunc("GET /{$}", s.overview)
	mux.HandleFunc("GET /members", s.members)
	mux.HandleFunc("GET /dividends", s.dividends)
	mux.HandleFunc("GET /audits", s.audits)
	mux.HandleFunc("GET /uniqueness", s.uniquenessPage)
	mux.HandleFunc("GET /ledger", s.ledgerPage)
	mux.HandleFunc("GET /ledger/{index}", s.entryPage)

	mux.HandleFunc("GET /officials/login", s.loginPage)
	mux.HandleFunc("POST /officials/login", s.login)
	mux.HandleFunc("POST /officials/logout", s.official("", s.logout))
	mux.HandleFunc("GET /officials", s.official("", s.fund))
	mux.HandleFunc("POST /officials/settle/{period}", s.official(store.RoleTreasurer, s.settle))
	mux.HandleFunc("POST /officials/resend/{id}", s.official(store.RoleTreasurer, s.resend))
	mux.HandleFunc("GET /officials/members", s.official("", s.officialsMembers))
	mux.HandleFunc("POST /officials/members/review", s.official(store.RoleMembers, s.reviewMember))
	mux.HandleFunc("POST /officials/members/attest", s.official(store.RoleMembers, s.attestMember))
	mux.HandleFunc("POST /officials/members/{instance}/status", s.official(store.RoleMembers, s.memberStatus))
	mux.HandleFunc("GET /officials/members/{instance}/attestation.json", s.official("", s.attestationFile))
	mux.HandleFunc("GET /officials/audits", s.official("", s.officialsAudits))
	mux.HandleFunc("GET /officials/audits/{request}", s.official("", s.auditPage))
	mux.HandleFunc("POST /officials/audits/{request}/check", s.official(store.RoleAuditor, s.fieldCheck))
	mux.HandleFunc("POST /officials/audits/{request}/finding", s.official(store.RoleAuditor, s.issueFinding))
	mux.HandleFunc("GET /officials/ledger", s.official("", s.officialsLedger))
	mux.HandleFunc("POST /officials/publish", s.official(store.RoleTreasurer, s.publish))
	mux.HandleFunc("GET /officials/team", s.official("", s.team))
	mux.HandleFunc("POST /officials/team", s.official(store.RoleAdmin, s.addOfficial))
	mux.HandleFunc("POST /officials/team/{username}/reset", s.official(store.RoleAdmin, s.resetOfficial))
	mux.HandleFunc("POST /officials/team/{username}/disable", s.official(store.RoleAdmin, s.disableOfficial))

	protocol := s.CW.ProtocolHandler()
	mux.Handle("/pc/", protocol)
	mux.Handle("/.well-known/", protocol)
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func cacheFor(d time.Duration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(d.Seconds())))
		h.ServeHTTP(w, r)
	})
}

// --- Templates ---------------------------------------------------------------

var typeLabels = map[string]string{
	dividend.EligibilityCountType: "Eligibility count",
	dividend.SettlementType:       "Dividend settlement",
	dividend.ConfirmationType:     "Dividend confirmation",
	audit.RequestType:             "Audit request",
	audit.FindingType:             "Audit finding",
	registry.DescriptionType:      "Instance description",
	registry.AttestationType:      "Member attestation",
	uniqueness.ConfigType:         "Uniqueness configuration",
}

type fingerprintView struct {
	Cells []int
	Hex   string
	Large bool
}

// fingerprint draws eight cells from the first four bytes of a record's
// ledger hash, so two copies of a record can be compared at a glance.
func fingerprint(env *record.Envelope, large bool) fingerprintView {
	h := entryHash(env)
	v := fingerprintView{Hex: hex.EncodeToString(h[:8]), Large: large}
	for _, b := range h[:4] {
		v.Cells = append(v.Cells, int(b>>4), int(b&0x0f))
	}
	return v
}

func entryHash(env *record.Envelope) ledger.Hash {
	entry, err := ledger.EntryBytes(env)
	if err != nil {
		return ledger.Hash{}
	}
	return ledger.LeafHash(entry)
}

// money formats a decimal amount for reading: thousands separators and at
// least two decimal places, for example "1,530.00".
func money(a string) string {
	if a == "" {
		return "–"
	}
	whole, frac, _ := strings.Cut(a, ".")
	for len(frac) < 2 {
		frac += "0"
	}
	var b strings.Builder
	for i, r := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String() + "." + frac
}

func fmtTimeT(t time.Time) string { return t.UTC().Format("2 Jan 2006, 15:04 MST") }

func fmtTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return fmtTimeT(t)
}

// keyFingerprint shortens a public key for reading aloud when confirming it
// with a member: the first 16 characters in groups of four.
func keyFingerprint(k string) string {
	k = strings.TrimPrefix(k, "ed25519:")
	if len(k) > 16 {
		k = k[:16]
	}
	var parts []string
	for len(k) > 4 {
		parts = append(parts, k[:4])
		k = k[4:]
	}
	return strings.Join(append(parts, k), " ")
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"fmtTime":        fmtTime,
		"fmtTimeT":       fmtTimeT,
		"summary":        commonwealth.Summary,
		"fingerprint":    fingerprint,
		"money":          money,
		"keyFingerprint": keyFingerprint,
		"typeLabel": func(t string) string {
			if l, ok := typeLabels[t]; ok {
				return l
			}
			return t
		},
	}
	s.pages = map[string]*template.Template{}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == "templates/base.html" {
			continue
		}
		t, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/base.html", name)
		if err != nil {
			return err
		}
		s.pages[strings.TrimSuffix(strings.TrimPrefix(name, "templates/"), ".html")] = t
	}
	return nil
}

// view is the data for every page; each page uses the fields it needs.
type view struct {
	Title, Section string
	Name, Instance string
	Official       bool
	Me             *store.Official
	CSRF           string
	Notice, Error  string

	StateCount, RegionCount int
	LedgerSize              uint64
	Latest                  *store.Period
	Members                 []store.Member
	Periods                 []periodView
	Audits                  []store.Audit
	Audit                   *store.Audit
	Openings                []store.Opening
	Config                  *uniqueness.Config
	ConfigRecord            *record.Envelope
	Uniqueness              []store.UniquenessSummary
	Review                  *registry.Description
	ReviewJSON              string
	Attestation             string
	Checkpoint              *checkpointView
	WitnessCount            int
	Entries                 []commonwealth.EntryStatus
	Entry                   *commonwealth.EntryStatus
	Hash, JSON              string
	Next                    string
	Officials               []store.Official
	ActionLog               []store.Action
	Roles                   []string
	NewPassword             string
	NewUsername             string
	Username                string
}

func (s *Server) newView(r *http.Request, title, section string) *view {
	v := &view{Title: title, Section: section, Name: s.CW.Name(), Instance: s.CW.Identity.Instance}
	if o, token, ok := s.session(r); ok {
		v.Official, v.Me, v.CSRF = true, o, s.csrfToken(token)
	}
	if msg, ok := notices[r.URL.Query().Get("done")]; ok {
		v.Notice = msg
	}
	return v
}

var notices = map[string]string{
	"settled":   "Period settled. Each State has been sent its settlement.",
	"resent":    "Record sent again.",
	"published": "Checkpoint published.",
	"status":    "Member's status updated.",
	"checked":   "Field check recorded.",
	"finding":   "Finding issued and sent. The sampled people's details have been erased.",
}

func (s *Server) render(w http.ResponseWriter, status int, page string, v *view) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}
	var buf strings.Builder
	if err := t.ExecuteTemplate(&buf, "base", v); err != nil {
		log.Printf("web: rendering %s: %v", page, err)
		http.Error(w, "could not render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprint(w, buf.String())
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	log.Printf("web: %v", err)
	http.Error(w, "Something went wrong. Try again, and check the server log if it keeps happening.", http.StatusInternalServerError)
}

// --- Sessions ----------------------------------------------------------------

func (s *Server) session(r *http.Request) (*store.Official, string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, "", false
	}
	o, err := s.Store.Session(c.Value)
	if err != nil {
		return nil, "", false
	}
	return o, c.Value, true
}

func (s *Server) csrfToken(sessionID string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("csrf:" + sessionID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

type ctxKey struct{}

// me returns the signed-in official of a request that went through official.
func me(r *http.Request) *store.Official {
	o, _ := r.Context().Value(ctxKey{}).(*store.Official)
	return o
}

// official wraps a handler that requires a signed-in official whose role
// allows the work (any official when role is empty). POST requests must
// also carry the session's CSRF token.
func (s *Server) official(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		o, token, ok := s.session(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/officials/login?next="+r.URL.Path, http.StatusSeeOther)
				return
			}
			http.Error(w, "Sign in again to continue.", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			want := s.csrfToken(token)
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(want)) != 1 {
				http.Error(w, "This form has expired. Go back, reload the page and try again.", http.StatusForbidden)
				return
			}
		}
		if role != "" && !o.Can(role) {
			http.Error(w, fmt.Sprintf("Your role (%s) does not allow this. Ask an admin.", o.Role), http.StatusForbidden)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, o)))
	}
}

// logAction records what the signed-in official did.
func (s *Server) logAction(r *http.Request, action, detail string) {
	o := me(r)
	if o == nil {
		return
	}
	if err := s.Store.LogAction(o.Username, action, detail); err != nil {
		log.Printf("web: logging action: %v", err)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.session(r); ok {
		http.Redirect(w, r, "/officials", http.StatusSeeOther)
		return
	}
	v := s.newView(r, "Officials' sign-in", "login")
	v.Next = safeNext(r.URL.Query().Get("next"))
	s.render(w, http.StatusOK, "login", v)
}

func safeNext(next string) string {
	if strings.HasPrefix(next, "/officials") && !strings.HasPrefix(next, "//") {
		return next
	}
	return "/officials"
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(strings.ToLower(r.PostFormValue("username")))
	o, err := s.Store.Authenticate(username, r.PostFormValue("password"))
	if errors.Is(err, store.ErrBadCredentials) {
		v := s.newView(r, "Officials' sign-in", "login")
		v.Next = safeNext(r.PostFormValue("next"))
		v.Username = username
		v.Error = "That username and password do not match an active account."
		s.render(w, http.StatusUnauthorized, "login", v)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	token, err := s.Store.NewSession(o.Username, sessionLength)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.LogAction(o.Username, "signed in", ""); err != nil {
		log.Printf("web: logging action: %v", err)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionLength.Seconds())})
	http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.Store.EndSession(c.Value); err != nil {
			log.Printf("web: ending session: %v", err)
		}
	}
	s.logAction(r, "signed out", "")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.SecureCookies})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
