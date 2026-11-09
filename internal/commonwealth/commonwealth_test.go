package commonwealth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/polycentric-commonwealth/foundation/audit"
	"github.com/polycentric-commonwealth/foundation/dividend"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
	"github.com/polycentric-commonwealth/foundation/uniqueness"

	"github.com/polycentric-commonwealth/platform-commonwealth/internal/store"
)

const cwID = "commonwealth.example"

// fakeState is a minimal State built from foundation packages: it reports
// counts, keeps what it receives and answers audits from its list.
type fakeState struct {
	id       protocol.Identity
	desc     *record.Envelope
	reg      *registry.Registry
	srv      *httptest.Server
	sender   *protocol.Sender
	refs     []string
	ghosts   map[string]bool
	entries  map[string][]audit.Entry // by count id
	mu       sync.Mutex
	received map[string][]*record.Envelope // by type
}

func (f *fakeState) got(typ string) []*record.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*record.Envelope{}, f.received[typ]...)
}

type harness struct {
	t      *testing.T
	cw     *Commonwealth
	db     *store.Store
	srv    *httptest.Server
	states map[string]*fakeState
	client *http.Client
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedDescription(t *testing.T, id string, layer record.Layer, parent, base string, pub ed25519.PublicKey, priv ed25519.PrivateKey) *record.Envelope {
	t.Helper()
	env, err := registry.NewDescription(&registry.Description{
		Instance: id, Layer: layer, Name: strings.Split(id, ".")[0], Parent: parent,
		Endpoints: map[string]string{"base": base + "/pc/"},
		Keys:      []registry.Key{{ID: "k1", PublicKey: registry.EncodePublicKey(pub), ValidFrom: "2026-01-01T00:00:00Z"}},
	}, "k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// start runs a Commonwealth and the named States over HTTPS. States whose
// names end in "!" are not attested.
func start(t *testing.T, states map[string]int, ghosts int) *harness {
	t.Helper()
	store.PasswordIterations = 1000
	h := &harness{t: t, states: map[string]*fakeState{}}
	var handler http.Handler = http.NotFoundHandler()
	h.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(h.srv.Certificate())
	fakes := map[string]*fakeState{}
	for name := range states {
		f := &fakeState{received: map[string][]*record.Envelope{}, entries: map[string][]audit.Entry{}, ghosts: map[string]bool{}}
		var fh http.Handler = http.NotFoundHandler()
		f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fh.ServeHTTP(w, r) }))
		f.srv.StartTLS()
		t.Cleanup(f.srv.Close)
		pool.AddCert(f.srv.Certificate())
		fakes[name] = f
		defer func(f *fakeState) {
			rv := &protocol.Receiver{Self: f.id, Registry: f.reg, Store: protocol.NewMemoryStore(), Handlers: map[string]protocol.Handler{}}
			keep := func(_ context.Context, env *record.Envelope) error {
				f.mu.Lock()
				f.received[env.Type] = append(f.received[env.Type], env)
				f.mu.Unlock()
				return nil
			}
			for _, typ := range []string{dividend.SettlementType, audit.FindingType, uniqueness.ConflictType} {
				rv.Handlers[typ] = keep
			}
			rv.Handlers[audit.RequestType] = func(ctx context.Context, env *record.Envelope) error {
				keep(ctx, env)
				go f.answer(t, env)
				return nil
			}
			mux := http.NewServeMux()
			mux.Handle("/pc/inbox", rv)
			fh = mux
		}(f)
	}
	h.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	// The Commonwealth.
	pub, priv := newKey(t)
	desc := signedDescription(t, cwID, record.Commonwealth, "", h.srv.URL, pub, priv)
	reg, err := registry.New(registry.Anchor{Instance: cwID, PublicKey: registry.EncodePublicKey(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.AddDescription(desc); err != nil {
		t.Fatal(err)
	}
	h.db, err = store.Open(filepath.Join(t.TempDir(), "cw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.db.Close() })
	h.cw, err = New(Config{
		Identity:    protocol.Identity{Instance: cwID, Layer: record.Commonwealth, KeyID: "k1", Key: priv},
		Description: desc, Registry: reg, Store: h.db, HTTP: h.client, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.cw.Close)
	handler = h.cw.ProtocolHandler()

	// The States, with their recipient lists.
	for name, n := range states {
		f := fakes[name]
		id := strings.TrimSuffix(name, "!") + ".example"
		spub, spriv := newKey(t)
		f.id = protocol.Identity{Instance: id, Layer: record.State, KeyID: "k1", Key: spriv}
		f.desc = signedDescription(t, id, record.State, cwID, f.srv.URL, spub, spriv)
		f.reg, _ = registry.New(registry.Anchor{Instance: cwID, PublicKey: registry.EncodePublicKey(pub)})
		f.reg.AddDescription(desc)
		f.sender = &protocol.Sender{Self: f.id, Registry: f.reg, HTTP: h.client}
		for i := range n {
			ref := fmt.Sprintf("%s-%03d", strings.ToUpper(id[:1]), i)
			f.refs = append(f.refs, ref)
			if i < ghosts && name == "north" {
				f.ghosts[ref] = true
			}
		}
		if strings.HasSuffix(name, "!") {
			// Known to the Commonwealth, but never attested.
			reg.AddDescription(f.desc)
		} else {
			data, _ := f.desc.Marshal()
			att, err := h.cw.AttestMember(context.Background(), data, "members-officer")
			if err != nil {
				t.Fatalf("attesting %s: %v", id, err)
			}
			if err := f.reg.AddAttestation(att); err != nil {
				t.Fatal(err)
			}
			f.reg.AddDescription(f.desc)
		}
		h.states[strings.TrimSuffix(name, "!")] = f
	}
	return h
}

// answer opens the sampled entries; ghosts get invented details.
func (f *fakeState) answer(t *testing.T, req *record.Envelope) {
	r, _ := audit.DecodeRequest(req)
	f.mu.Lock()
	entries := f.entries[r.Count]
	var count *record.Envelope
	for _, c := range f.received["sent-count"] {
		if c.ID == r.Count {
			count = c
		}
	}
	f.mu.Unlock()
	resp, err := audit.Open(count, req, entries, func(ref string) (audit.Person, error) {
		return audit.Person{Name: "Person " + ref, BirthDate: "1980-01-01"}, nil
	})
	if err != nil {
		t.Errorf("%s opening: %v", f.id.Instance, err)
		return
	}
	env, _ := f.id.Message(req.Issuer, audit.ResponseType, resp)
	if _, err := f.sender.Send(context.Background(), env); err != nil {
		t.Errorf("%s answering audit: %v", f.id.Instance, err)
	}
}

func (f *fakeState) report(t *testing.T, period string) (*record.Envelope, error) {
	t.Helper()
	entries, root, err := audit.BuildList(f.refs)
	if err != nil {
		t.Fatal(err)
	}
	c := dividend.EligibilityCount{Period: period, Residents: int64(len(f.refs)), Adults: int64(len(f.refs)),
		DividendRecipients: int64(len(f.refs)), RecipientsRoot: ledger.EncodeHash(root)}
	env, err := f.id.Message(cwID, dividend.EligibilityCountType, c)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.entries[env.ID] = entries
	f.received["sent-count"] = append(f.received["sent-count"], env)
	f.mu.Unlock()
	_, err = f.sender.Send(context.Background(), env)
	return env, err
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestPerPerson(t *testing.T) {
	for _, c := range []struct {
		pool       string
		recipients int64
		per, paid  string
	}{
		{"100", 15, "6.666666", "99.99999"},
		{"1000000", 4, "250000", "1000000"},
		{"0.000001", 1, "0.000001", "0.000001"},
	} {
		per, paid, err := PerPerson(c.pool, c.recipients)
		if err != nil || per != c.per || paid != c.paid {
			t.Errorf("PerPerson(%s, %d) = %s, %s, %v; want %s, %s", c.pool, c.recipients, per, paid, err, c.per, c.paid)
		}
	}
	if _, _, err := PerPerson("0.000001", 2); err == nil {
		t.Error("a pool too small to pay anyone was accepted")
	}
}

func TestDividendCycleAndAudit(t *testing.T) {
	h := start(t, map[string]int{"north": 10, "south": 5, "rogue!": 3}, 2)
	north, south, rogue := h.states["north"], h.states["south"], h.states["rogue"]
	ctx := context.Background()

	// Members report; an unattested State and a second count are refused.
	nc, err := north.report(t, "2027-01")
	if err != nil {
		t.Fatalf("north report: %v", err)
	}
	if _, err := south.report(t, "2027-01"); err != nil {
		t.Fatalf("south report: %v", err)
	}
	if _, err := rogue.report(t, "2027-01"); !errors.Is(err, protocol.ErrRejected) || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("rogue report: %v", err)
	}
	if _, err := north.report(t, "2027-01"); !errors.Is(err, protocol.ErrRejected) {
		t.Errorf("second north report: %v", err)
	}

	// Every accepted count is audited at once; the States answer.
	waitFor(t, "both audits to be answered", func() bool {
		list, _ := h.db.Audits()
		return len(list) == 2 && list[0].Status == "checking" && list[1].Status == "checking"
	})

	// Settle: 100 XCU among 15 recipients.
	per, err := h.cw.SettlePeriod(ctx, "2027-01", "100", "treasurer")
	if err != nil || per != "6.666666" {
		t.Fatalf("settle: %s, %v", per, err)
	}
	if _, err := h.cw.SettlePeriod(ctx, "2027-01", "100", "treasurer"); !errors.Is(err, store.ErrPeriodSettled) {
		t.Errorf("second settlement: %v", err)
	}
	if got := north.got(dividend.SettlementType); len(got) != 1 {
		t.Fatalf("north got %d settlements", len(got))
	} else if s, _ := dividend.DecodeSettlement(got[0]); s.CheckAgainst(nc) != nil || s.Total != "66.66666" {
		t.Errorf("north settlement %+v does not match its count", s)
	}
	if _, err := south.report(t, "2027-01"); !errors.Is(err, protocol.ErrRejected) {
		t.Errorf("count after settlement: %v", err)
	}

	// North pays and confirms.
	s, _ := dividend.DecodeSettlement(north.got(dividend.SettlementType)[0])
	conf, _ := north.id.Message(cwID, dividend.ConfirmationType, dividend.Confirmation{
		Settlement: north.got(dividend.SettlementType)[0].ID, Unit: s.Unit, PaidRecipients: s.Recipients, PaidTotal: s.Total})
	if _, err := north.sender.Send(ctx, conf); err != nil {
		t.Errorf("confirmation: %v", err)
	}

	// Auditors check North's sample in the field; its two ghosts are not
	// found. A finding cannot be issued until every person is checked.
	var audits map[string]store.Audit = map[string]store.Audit{}
	list, _ := h.db.Audits()
	for _, a := range list {
		audits[a.State] = a
	}
	na := audits["north.example"]
	if _, err := h.cw.IssueFinding(ctx, na.Request, "auditor"); !errors.Is(err, ErrAuditNotReady) {
		t.Errorf("early finding: %v", err)
	}
	openings, _ := h.db.Openings(na.Request)
	if len(openings) != 10 {
		t.Fatalf("north audit has %d openings", len(openings))
	}
	for _, o := range openings {
		if !o.Valid || o.Name == "" {
			t.Errorf("opening %d: valid %v, name %q, problem %q", o.Position, o.Valid, o.Name, o.Problem)
		}
		if err := h.db.RecordFieldCheck(na.Request, o.Position, !north.ghosts[o.Ref], "auditor"); err != nil {
			t.Fatal(err)
		}
	}
	f, err := h.cw.IssueFinding(ctx, na.Request, "auditor")
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if f.Unverified != 2 || f.EstimatedExcess != 2 || f.Repayment != "39.999996" {
		t.Errorf("finding = %+v", f)
	}
	waitFor(t, "north to receive the finding", func() bool { return len(north.got(audit.FindingType)) == 1 })

	// The sampled people's details are erased; the outcomes remain.
	openings, _ = h.db.Openings(na.Request)
	for _, o := range openings {
		if o.Name != "" || o.Ref != "" || o.BirthDate != "" || o.Field == "" {
			t.Fatalf("opening %d still holds personal data or lost its outcome: %+v", o.Position, o)
		}
	}
	// The response itself was never stored with its payload.
	recs, _ := h.db.Records(audit.ResponseType, 10)
	for _, r := range recs {
		if strings.Contains(string(r.Envelope.Payload), "Person") {
			t.Error("an audit response was stored with personal data")
		}
	}

	// Everything the Commonwealth issued is in its ledger and verifies.
	entries, err := h.cw.LedgerEntries(50)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, e := range entries {
		types[e.Envelope.Type]++
		if e.Signed != nil {
			t.Errorf("entry %d: %v", e.Index, e.Signed)
		}
	}
	want := map[string]int{registry.AttestationType: 2, audit.RequestType: 2, dividend.SettlementType: 2, audit.FindingType: 1}
	for typ, n := range want {
		if types[typ] != n {
			t.Errorf("ledger has %d %s, want %d", types[typ], typ, n)
		}
	}
	if types[audit.ResponseType]+types[dividend.EligibilityCountType] != 0 {
		t.Error("the ledger holds records the Commonwealth did not issue")
	}
	periods, _ := h.db.Periods()
	if len(periods) != 1 || periods[0].PaidOut != "99.99999" || periods[0].Recipients != 15 {
		t.Errorf("periods = %+v", periods)
	}
	counts, _ := h.db.Counts("2027-01")
	if counts[0].Confirmation == "" || counts[1].Confirmation != "" {
		t.Errorf("confirmations: %+v", counts)
	}
}

func TestSuspendedMember(t *testing.T) {
	h := start(t, map[string]int{"north": 3}, 0)
	if err := h.db.SetMemberStatus("north.example", "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.states["north"].report(t, "2027-02"); !errors.Is(err, protocol.ErrRejected) || !strings.Contains(err.Error(), "suspended") {
		t.Errorf("suspended State's count: %v", err)
	}
}

func TestUniquenessRegistry(t *testing.T) {
	h := start(t, map[string]int{"north": 1, "south": 1}, 0)
	ctx := context.Background()
	north, south := h.states["north"], h.states["south"]
	register := func(f *fakeState, epoch int64, add ...string) error {
		env, _ := f.id.Message(cwID, uniqueness.RegistrationType, uniqueness.Registration{Epoch: epoch, Add: add})
		_, err := f.sender.Send(ctx, env)
		return err
	}
	tok := func(b byte) string { return uniqueness.Token(append([]byte{b}, make([]byte, 63)...)) }
	if err := register(north, 1, tok(1)); !errors.Is(err, protocol.ErrRejected) {
		t.Errorf("registration before any configuration: %v", err)
	}

	commitments, _, err := uniqueness.Deal(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &uniqueness.Config{Suite: uniqueness.SuiteID, Epoch: 1, Commitments: commitments, Registry: cwID,
		Operators: []uniqueness.Operator{{Instance: "op1.example", Index: 1}, {Instance: "op2.example", Index: 2}, {Instance: "op3.example", Index: 3}}}
	if _, err := h.cw.SetUniquenessConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := h.cw.SetUniquenessConfig(ctx, cfg); err == nil {
		t.Error("a configuration with the same epoch was accepted")
	}
	resp, err := h.client.Get(h.srv.URL + "/pc/" + UniquenessConfigPath)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("config endpoint: %v %v", resp, err)
	}
	resp.Body.Close()

	if err := register(north, 1, tok(1), tok(2)); err != nil {
		t.Fatal(err)
	}
	if err := register(south, 2, tok(2)); !errors.Is(err, protocol.ErrRejected) {
		t.Errorf("registration for the wrong epoch: %v", err)
	}
	if err := register(south, 1, tok(2), tok(3)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []*fakeState{north, south} {
		waitFor(t, f.id.Instance+" to hear of the conflict", func() bool { return len(f.got(uniqueness.ConflictType)) == 1 })
		c, err := uniqueness.DecodeConflict(f.got(uniqueness.ConflictType)[0])
		if err != nil || c.Token != tok(2) || strings.Join(c.States, ",") != "north.example,south.example" {
			t.Errorf("%s conflict = %+v, %v", f.id.Instance, c, err)
		}
	}
	sum, _ := h.db.Uniqueness(1)
	if len(sum) != 2 || sum[0].Tokens != 2 || sum[0].Conflicts != 1 || sum[1].Conflicts != 1 {
		t.Errorf("summary = %+v", sum)
	}
	// The person moved: North removes the token and the conflict closes.
	env, _ := north.id.Message(cwID, uniqueness.RegistrationType, uniqueness.Registration{Epoch: 1, Remove: []string{tok(2)}})
	if _, err := north.sender.Send(ctx, env); err != nil {
		t.Fatal(err)
	}
	if sum, _ = h.db.Uniqueness(1); sum[0].Tokens != 1 || sum[0].Conflicts != 0 || sum[1].Conflicts != 0 {
		t.Errorf("after removal: %+v", sum)
	}
}
