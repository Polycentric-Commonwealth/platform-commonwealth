package web_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"

	"github.com/polycentric-commonwealth/platform-commonwealth/internal/deploy"
	"github.com/polycentric-commonwealth/platform-commonwealth/internal/store"
	"github.com/polycentric-commonwealth/platform-commonwealth/internal/web"
)

const password = "correct horse battery"

func TestMain(m *testing.M) {
	store.PasswordIterations = 1000
	os.Exit(m.Run())
}

func start(t *testing.T) (*httptest.Server, *deploy.Instance) {
	t.Helper()
	dir := t.TempDir()
	if _, err := deploy.Init(dir, deploy.Config{Instance: "commonwealth.example", Name: "Commonwealth", BaseURL: "https://commonwealth.example/", Listen: ":0"}); err != nil {
		t.Fatal(err)
	}
	in, err := deploy.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	for _, o := range [][3]string{{"admin", "Ada Admin", store.RoleAdmin}, {"mo", "Mo Members", store.RoleMembers}, {"aud", "Aud Itor", store.RoleAuditor}} {
		if err := in.Store.AddOfficial(o[0], o[1], o[2], password); err != nil {
			t.Fatal(err)
		}
	}
	site, err := web.New(in.CW, in.Store, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(site)
	t.Cleanup(srv.Close)
	return srv, in
}

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, c *http.Client, u string, form url.Values) (*http.Response, string) {
	t.Helper()
	var resp *http.Response
	var err error
	if form == nil {
		resp, err = c.Get(u)
	} else {
		resp, err = c.PostForm(u, form)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func signIn(t *testing.T, srv *httptest.Server, user string) (*http.Client, string) {
	t.Helper()
	c := client()
	if resp, _ := do(t, c, srv.URL+"/officials/login", url.Values{"username": {user}, "password": {password}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login as %s: %d", user, resp.StatusCode)
	}
	_, page := do(t, c, srv.URL+"/officials", nil)
	m := csrfPattern.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSRF token")
	}
	return c, m[1]
}

func stateDescription(t *testing.T, id, parent string) string {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, err := registry.NewDescription(&registry.Description{
		Instance: id, Layer: record.State, Name: "North", Parent: parent,
		Endpoints: map[string]string{"base": "https://" + id + "/pc/"},
		Keys:      []registry.Key{{ID: "k1", PublicKey: registry.EncodePublicKey(pub), ValidFrom: "2026-01-01T00:00:00Z"}},
	}, "k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.Marshal()
	return string(data)
}

func TestPublicPages(t *testing.T) {
	srv, _ := start(t)
	c := client()
	for _, path := range []string{"/", "/members", "/dividends", "/audits", "/uniqueness", "/ledger", "/officials/login", "/static/style.css", "/.well-known/pc-instance", "/.well-known/pc-attestations"} {
		resp, _ := do(t, c, srv.URL+path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", path, resp.StatusCode)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("%s: no Content-Security-Policy", path)
		}
	}
	if resp, _ := do(t, c, srv.URL+"/pc/uniqueness/config", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("uniqueness config before publication: %d", resp.StatusCode)
	}
	if resp, _ := do(t, c, srv.URL+"/officials/audits", nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("officials page without signing in: %d", resp.StatusCode)
	}
}

func TestAttestMember(t *testing.T) {
	srv, in := start(t)
	mo, csrf := signIn(t, srv, "mo")
	desc := stateDescription(t, "north.example", "commonwealth.example")

	// Review shows the key fingerprint; attesting needs the confirmation box.
	resp, page := do(t, mo, srv.URL+"/officials/members/review", url.Values{"description": {desc}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Attest north.example") || !strings.Contains(page, `class="keyprint"`) {
		t.Fatalf("review: %d", resp.StatusCode)
	}
	if resp, _ := do(t, mo, srv.URL+"/officials/members/attest", url.Values{"description": {desc}, "csrf": {csrf}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("attest without confirming: %d", resp.StatusCode)
	}
	resp, page = do(t, mo, srv.URL+"/officials/members/attest", url.Values{"description": {desc}, "confirmed": {"yes"}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(html.UnescapeString(page), `"instance-attestation/1"`) {
		t.Fatalf("attest: %d", resp.StatusCode)
	}
	m, err := in.Store.Member("north.example")
	if err != nil || m.AttestedBy != "mo" || m.Status != "active" {
		t.Fatalf("member = %+v, %v", m, err)
	}
	if _, ok := in.CW.Registry.Description("north.example"); !ok {
		t.Error("the attested member is not in the registry")
	}
	resp, file := do(t, mo, srv.URL+"/officials/members/north.example/attestation.json", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(file, `"subject": "north.example"`) {
		t.Errorf("attestation download: %d", resp.StatusCode)
	}
	_, page = do(t, client(), srv.URL+"/members", nil)
	if !strings.Contains(page, "north.example") {
		t.Error("public members page does not list the member")
	}
	_, page = do(t, client(), srv.URL+"/ledger", nil)
	if !strings.Contains(page, "Member attestation") {
		t.Error("the attestation is not in the public ledger")
	}
	if resp, _ := do(t, client(), srv.URL+"/ledger/0", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("ledger entry page: %d", resp.StatusCode)
	}

	// A State whose parent is a Region is refused; suspension works.
	other := stateDescription(t, "south.example", "region.example")
	if resp, _ := do(t, mo, srv.URL+"/officials/members/attest", url.Values{"description": {other}, "confirmed": {"yes"}, "csrf": {csrf}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("attesting another parent's State: %d", resp.StatusCode)
	}
	if resp, _ := do(t, mo, srv.URL+"/officials/members/north.example/status", url.Values{"status": {"suspended"}, "csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("suspend: %d", resp.StatusCode)
	}
	if m, _ := in.Store.Member("north.example"); m.Status != "suspended" {
		t.Error("member not suspended")
	}

	// Roles: an auditor cannot attest or settle; nobody can settle an empty
	// period.
	aud, acsrf := signIn(t, srv, "aud")
	if resp, _ := do(t, aud, srv.URL+"/officials/members/attest", url.Values{"description": {desc}, "confirmed": {"yes"}, "csrf": {acsrf}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("auditor attesting: %d", resp.StatusCode)
	}
	if resp, _ := do(t, aud, srv.URL+"/officials/settle/2027-01", url.Values{"pool": {"100"}, "csrf": {acsrf}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("auditor settling: %d", resp.StatusCode)
	}
	admin, ccsrf := signIn(t, srv, "admin")
	if resp, _ := do(t, admin, srv.URL+"/officials/settle/2027-01", url.Values{"pool": {"100"}, "csrf": {ccsrf}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("settling an empty period: %d", resp.StatusCode)
	}
	_, page = do(t, admin, srv.URL+"/officials/team", nil)
	if !strings.Contains(page, "attested member") || !strings.Contains(page, "set member status") {
		t.Error("activity log is missing member actions")
	}
}
