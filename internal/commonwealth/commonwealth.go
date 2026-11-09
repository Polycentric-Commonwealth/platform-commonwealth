// Package commonwealth is the Commonwealth platform's core: it holds the
// Commonwealth's identity, registry, database and public ledger, attests
// member instances, settles dividends through the Commons Fund, runs the
// Audit Office's eligibility audits and keeps the uniqueness registry.
package commonwealth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/polycentric-commonwealth/foundation/amount"
	"github.com/polycentric-commonwealth/foundation/audit"
	"github.com/polycentric-commonwealth/foundation/dividend"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
	"github.com/polycentric-commonwealth/foundation/uniqueness"

	"github.com/polycentric-commonwealth/platform-commonwealth/internal/store"
)

// UniquenessConfigPath is where the uniqueness configuration is served,
// relative to the protocol base.
const UniquenessConfigPath = "uniqueness/config"

const uniquenessConfigSetting = "uniqueness-config"

// Config describes a Commonwealth instance.
type Config struct {
	Identity    protocol.Identity
	Description *record.Envelope // the Commonwealth's signed instance description
	Registry    *registry.Registry
	Store       *store.Store
	Witnesses   ledger.WitnessPolicy // witnesses asked to cosign, and the policy used to check evidence
	HTTP        *http.Client
	Now         func() time.Time // defaults to time.Now

	// Multiplier applies to audit repayments; it defaults to
	// audit.DefaultMultiplier.
	Multiplier string

	// Discover, if set, fetches an unknown instance's description and
	// attestations into the registry (registry.Fetcher.Discover).
	Discover func(ctx context.Context, instance string) error

	// Logf reports background problems.
	Logf func(format string, args ...any)
}

// Commonwealth is a running Commonwealth instance.
type Commonwealth struct {
	Config
	Log      *ledger.Log
	Receiver *protocol.Receiver
	Sender   *protocol.Sender
	Witness  *ledger.Witness

	wg sync.WaitGroup
}

// New returns a Commonwealth ready to serve.
func New(cfg Config) (*Commonwealth, error) {
	if cfg.Identity.Layer != record.Commonwealth {
		return nil, fmt.Errorf("commonwealth: identity is a %s instance", cfg.Identity.Layer)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Multiplier == "" {
		cfg.Multiplier = audit.DefaultMultiplier
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	c := &Commonwealth{Config: cfg}
	log, err := ledger.OpenLog(cfg.Identity, store.Ledger{S: cfg.Store})
	if err != nil {
		return nil, fmt.Errorf("commonwealth: opening the ledger: %w", err)
	}
	c.Log = log
	c.Sender = &protocol.Sender{Self: cfg.Identity, Registry: cfg.Registry, HTTP: cfg.HTTP}
	c.Receiver = &protocol.Receiver{
		Self:     cfg.Identity,
		Registry: cfg.Registry,
		Store:    store.Inbox{S: cfg.Store},
		Now:      cfg.Now,
		Discover: cfg.Discover,
		Handlers: map[string]protocol.Handler{
			dividend.EligibilityCountType: c.receiveCount,
			dividend.ConfirmationType:     c.receiveConfirmation,
			audit.ResponseType:            c.receiveAuditResponse,
			uniqueness.RegistrationType:   c.receiveRegistration,
		},
	}
	c.Witness = &ledger.Witness{Self: cfg.Identity, Registry: cfg.Registry, Store: store.Witnessed{S: cfg.Store}, Now: cfg.Now, Discover: cfg.Discover}
	return c, nil
}

// Close waits for background work to finish.
func (c *Commonwealth) Close() { c.wg.Wait() }

func (c *Commonwealth) background(what string, f func(ctx context.Context) error) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := f(ctx); err != nil {
			c.Logf("commonwealth: %s: %v", what, err)
		}
	}()
}

// Name returns the Commonwealth's human-readable name.
func (c *Commonwealth) Name() string {
	if d, ok := c.Registry.Description(c.Identity.Instance); ok {
		return d.Name
	}
	return c.Identity.Instance
}

// ProtocolHandler serves the endpoints other instances use. Mount it at the
// root; it handles paths under /pc/ and /.well-known/.
func (c *Commonwealth) ProtocolHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/pc/"+protocol.InboxPath, c.Receiver)
	mux.Handle("/pc/"+ledger.WitnessPath, c.Witness)
	mux.Handle("/pc/ledger/", http.StripPrefix("/pc/ledger", c.Log.Handler()))
	mux.HandleFunc("GET /pc/"+UniquenessConfigPath, func(w http.ResponseWriter, r *http.Request) {
		env, _, err := c.UniquenessConfig()
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no uniqueness configuration has been published", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "could not read the configuration", http.StatusInternalServerError)
			return
		}
		writeRecord(w, env)
	})
	mux.HandleFunc("GET "+registry.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		writeRecord(w, c.Description)
	})
	mux.HandleFunc("GET "+registry.AttestationsPath, func(w http.ResponseWriter, r *http.Request) {
		// The Commonwealth is a trust anchor: nobody attests it.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]\n"))
	})
	return mux
}

func writeRecord(w http.ResponseWriter, env *record.Envelope) {
	data, err := env.Marshal()
	if err != nil {
		http.Error(w, "could not encode record", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// Members

// AttestMember attests every current key in a Region's or State's signed
// description, records the instance as a member and logs the attestation.
// Officials must confirm the keys with the member out of band first.
func (c *Commonwealth) AttestMember(ctx context.Context, description []byte, actor string) (*record.Envelope, error) {
	env, err := record.Parse(description)
	if err != nil {
		return nil, err
	}
	d, err := registry.ParseDescription(env)
	if err != nil {
		return nil, err
	}
	if d.Layer != record.Region && d.Layer != record.State {
		return nil, fmt.Errorf("commonwealth: only Regions and States are attested here, not a %s", d.Layer)
	}
	if d.Parent != c.Identity.Instance {
		return nil, fmt.Errorf("commonwealth: %s names %q as its parent; its parent must attest it", d.Instance, d.Parent)
	}
	k, ok := d.Key(env.Key)
	if !ok {
		return nil, fmt.Errorf("commonwealth: the description is signed with key %q, which it does not list", env.Key)
	}
	pub, err := registry.DecodePublicKey(k.PublicKey)
	if err == nil {
		err = env.Verify(pub)
	}
	if err != nil {
		return nil, fmt.Errorf("commonwealth: the description is not signed by its own key: %w", err)
	}
	a := &registry.Attestation{Subject: d.Instance, SubjectLayer: d.Layer}
	for _, k := range d.Keys {
		if k.RevokedAt == "" {
			a.Keys = append(a.Keys, registry.AttestedKey{ID: k.ID, PublicKey: k.PublicKey})
		}
	}
	att, err := registry.NewAttestation(c.Identity.Instance, record.Commonwealth, c.Identity.KeyID, c.Identity.Key, a)
	if err != nil {
		return nil, err
	}
	if err := c.Registry.AddAttestation(att); err != nil {
		return nil, err
	}
	if err := c.Registry.AddDescription(env); err != nil && !errors.Is(err, registry.ErrStale) {
		return nil, err
	}
	if err := c.Store.SaveMember(env, att, string(d.Layer), d.Name, actor); err != nil {
		return nil, err
	}
	if _, err := c.Log.Append(att); err != nil {
		return nil, err
	}
	_, err = c.PublishLedger(ctx)
	return att, err
}

// memberState checks that a record's issuer is a State in good standing:
// attested by the Commonwealth or by a Region that is, and not suspended.
func (c *Commonwealth) memberState(instance string) error {
	d, ok := c.Registry.Description(instance)
	if !ok || d.Layer != record.State {
		return fmt.Errorf("%s is not a known State", instance)
	}
	if m, err := c.Store.Member(instance); err == nil {
		if m.Status != "active" {
			return fmt.Errorf("%s is suspended", instance)
		}
		return nil
	}
	if m, err := c.Store.Member(d.Parent); err == nil && m.Layer == string(record.Region) {
		if m.Status != "active" {
			return fmt.Errorf("%s's Region %s is suspended", instance, d.Parent)
		}
		return nil
	}
	return fmt.Errorf("%s is not a member State", instance)
}

// Commons Fund

func (c *Commonwealth) receiveCount(_ context.Context, env *record.Envelope) error {
	count, err := dividend.DecodeCount(env)
	if err != nil {
		return err
	}
	if err := c.memberState(env.Issuer); err != nil {
		return err
	}
	switch err := c.Store.SaveCount(env, count); {
	case errors.Is(err, store.ErrPeriodSettled):
		return fmt.Errorf("period %s has already been settled; counts are no longer accepted for it", count.Period)
	case errors.Is(err, store.ErrDuplicateCount):
		return fmt.Errorf("a count for %s was already accepted from %s", count.Period, env.Issuer)
	case err != nil:
		return err
	}
	if count.DividendRecipients > 0 {
		c.background("starting audit of "+env.ID, func(ctx context.Context) error { return c.StartAudit(ctx, env) })
	}
	return nil
}

// ErrNothingToSettle reports a period with no counts.
var ErrNothingToSettle = errors.New("commonwealth: the period has no counts to settle")

// PerPerson divides a pool among recipients, rounding down to a millionth
// of an XCU. The remainder stays in the Commons Fund.
func PerPerson(pool string, recipients int64) (perPerson, paidOut string, err error) {
	p, err := amount.Parse(pool)
	if err != nil {
		return "", "", err
	}
	if recipients < 1 {
		return "", "", ErrNothingToSettle
	}
	micro := new(big.Rat).Mul(p, big.NewRat(1_000_000, recipients))
	floor := new(big.Int).Quo(micro.Num(), micro.Denom())
	if floor.Sign() == 0 {
		return "", "", fmt.Errorf("commonwealth: the pool is too small to pay %d recipients", recipients)
	}
	perPerson, err = amount.Format(new(big.Rat).SetFrac(floor, big.NewInt(1_000_000)))
	if err != nil {
		return "", "", err
	}
	paidOut, err = amount.MulInt(perPerson, recipients)
	return perPerson, paidOut, err
}

// SettlePeriod closes a period: it divides the pool equally among every
// recipient counted by every State, sends each State its settlement and
// logs them. Counts arriving afterwards are refused.
func (c *Commonwealth) SettlePeriod(ctx context.Context, period, pool, actor string) (perPerson string, err error) {
	counts, err := c.Store.Counts(period)
	if err != nil {
		return "", err
	}
	if len(counts) == 0 {
		return "", ErrNothingToSettle
	}
	var total int64
	for _, n := range counts {
		total += n.Recipients
	}
	perPerson, paidOut, err := PerPerson(pool, total)
	if err != nil {
		return "", err
	}
	settlements := map[string]*record.Envelope{}
	for _, n := range counts {
		rec, err := c.Store.Record(n.Record)
		if err != nil {
			return "", err
		}
		s, err := dividend.NewSettlement(rec.Envelope, perPerson)
		if err != nil {
			return "", err
		}
		env, err := c.Identity.Message(n.State, dividend.SettlementType, s)
		if err != nil {
			return "", err
		}
		settlements[n.Record] = env
	}
	if err := c.Store.SettlePeriod(period, pool, perPerson, paidOut, total, actor, settlements); err != nil {
		return "", err
	}
	var errs []error
	for _, env := range settlements {
		if _, err := c.Log.Append(env); err != nil {
			return "", err
		}
		if err := c.deliver(ctx, env); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", env.To, err))
		}
	}
	if _, err := c.PublishLedger(ctx); err != nil {
		errs = append(errs, err)
	}
	return perPerson, errors.Join(errs...)
}

func (c *Commonwealth) receiveConfirmation(_ context.Context, env *record.Envelope) error {
	conf, err := dividend.DecodeConfirmation(env)
	if err != nil {
		return err
	}
	rec, err := c.Store.Record(conf.Settlement)
	if err != nil || rec.Direction != "sent" || rec.Envelope.To != env.Issuer {
		return fmt.Errorf("no settlement %s was sent to %s", conf.Settlement, env.Issuer)
	}
	if err := conf.CheckAgainst(rec.Envelope); err != nil {
		return err
	}
	// The State logs its own confirmation; the Commonwealth only records it.
	return c.Store.SaveConfirmation(env, conf.Settlement)
}

// Audit Office

// StartAudit asks a State to open a random sample of a count's recipient
// list. The request is a public act and is logged.
func (c *Commonwealth) StartAudit(ctx context.Context, count *record.Envelope) error {
	req, err := audit.NewRequest(count)
	if err != nil {
		return err
	}
	env, err := c.Identity.Message(count.Issuer, audit.RequestType, req)
	if err != nil {
		return err
	}
	if err := c.Store.SaveAuditRequest(env, count.ID); err != nil {
		return err
	}
	return c.logAndSend(ctx, env)
}

func (c *Commonwealth) receiveAuditResponse(_ context.Context, env *record.Envelope) error {
	var head struct {
		Request string `json:"request"`
	}
	if err := json.Unmarshal(env.Payload, &head); err != nil {
		return err
	}
	a, err := c.Store.Audit(head.Request)
	if err != nil || a.State != env.Issuer {
		return fmt.Errorf("no audit %s of %s", head.Request, env.Issuer)
	}
	if a.Status != "requested" {
		return fmt.Errorf("audit %s has already been answered", head.Request)
	}
	count, err := c.Store.Record(a.Count)
	if err != nil {
		return err
	}
	request, err := c.Store.Record(a.Request)
	if err != nil {
		return err
	}
	results, err := audit.Check(count.Envelope, request.Envelope, env)
	if err != nil {
		return err
	}
	return c.Store.SaveAuditResults(a.Request, results)
}

// ErrAuditNotReady reports an audit that cannot have its finding yet.
var ErrAuditNotReady = errors.New("commonwealth: the audit is not ready for a finding")

// IssueFinding computes and sends the finding of an audit whose sampled
// people have all been checked in the field, and erases their details.
func (c *Commonwealth) IssueFinding(ctx context.Context, request, actor string) (*audit.Finding, error) {
	a, err := c.Store.Audit(request)
	if err != nil {
		return nil, err
	}
	if a.Status != "checking" {
		return nil, fmt.Errorf("%w: it is %s", ErrAuditNotReady, a.Status)
	}
	if a.Pending > 0 {
		return nil, fmt.Errorf("%w: %d sampled people have not been checked yet", ErrAuditNotReady, a.Pending)
	}
	n, err := c.Store.CountByRecord(a.Count)
	if err != nil {
		return nil, err
	}
	if n.Settlement == "" {
		return nil, fmt.Errorf("%w: period %s has not been settled, so there is no dividend to measure the finding against", ErrAuditNotReady, n.Period)
	}
	openings, err := c.Store.Openings(request)
	if err != nil {
		return nil, err
	}
	unverified := 0
	for _, o := range openings {
		if !o.Valid || o.Field == "not-found" {
			unverified++
		}
	}
	count, err := c.Store.Record(a.Count)
	if err != nil {
		return nil, err
	}
	req, err := c.Store.Record(a.Request)
	if err != nil {
		return nil, err
	}
	srec, err := c.Store.Record(n.Settlement)
	if err != nil {
		return nil, err
	}
	s, err := dividend.DecodeSettlement(srec.Envelope)
	if err != nil {
		return nil, err
	}
	f, err := audit.NewFinding(count.Envelope, req.Envelope, s, len(openings), unverified, c.Multiplier)
	if err != nil {
		return nil, err
	}
	env, err := c.Identity.Message(a.State, audit.FindingType, f)
	if err != nil {
		return nil, err
	}
	if err := c.Store.FinishAudit(request, unverified, env, actor); err != nil {
		return nil, err
	}
	return f, c.logAndSend(ctx, env)
}

// Uniqueness registry

// SetUniquenessConfig signs, stores and logs a new uniqueness
// configuration. The registry it names must be this Commonwealth.
func (c *Commonwealth) SetUniquenessConfig(ctx context.Context, cfg *uniqueness.Config) (*record.Envelope, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Registry != c.Identity.Instance {
		return nil, fmt.Errorf("commonwealth: the configuration names %s as the registry, not this Commonwealth", cfg.Registry)
	}
	if _, old, err := c.UniquenessConfig(); err == nil && cfg.Epoch <= old.Epoch {
		return nil, fmt.Errorf("commonwealth: a new configuration needs an epoch above %d", old.Epoch)
	}
	env, err := c.Identity.Message("", uniqueness.ConfigType, cfg)
	if err != nil {
		return nil, err
	}
	if err := c.Store.SaveSent(env); err != nil {
		return nil, err
	}
	if err := c.Store.SetDelivery(env.ID, "published"); err != nil {
		return nil, err
	}
	if err := c.Store.SetSetting(uniquenessConfigSetting, []byte(env.ID)); err != nil {
		return nil, err
	}
	if _, err := c.Log.Append(env); err != nil {
		return nil, err
	}
	_, err = c.PublishLedger(ctx)
	return env, err
}

// UniquenessConfig returns the current uniqueness configuration.
func (c *Commonwealth) UniquenessConfig() (*record.Envelope, *uniqueness.Config, error) {
	id, err := c.Store.Setting(uniquenessConfigSetting)
	if err != nil {
		return nil, nil, err
	}
	rec, err := c.Store.Record(string(id))
	if err != nil {
		return nil, nil, err
	}
	cfg, err := uniqueness.DecodeConfig(rec.Envelope)
	return rec.Envelope, cfg, err
}

func (c *Commonwealth) receiveRegistration(_ context.Context, env *record.Envelope) error {
	reg, err := uniqueness.DecodeRegistration(env)
	if err != nil {
		return err
	}
	if err := c.memberState(env.Issuer); err != nil {
		return err
	}
	_, cfg, err := c.UniquenessConfig()
	if err != nil {
		return errors.New("no uniqueness configuration has been published")
	}
	if reg.Epoch != cfg.Epoch {
		return fmt.Errorf("registrations are for epoch %d", cfg.Epoch)
	}
	conflicts, err := c.Store.ApplyRegistration(env.Issuer, reg)
	if err != nil {
		return err
	}
	for _, cf := range conflicts {
		for _, st := range cf.States {
			c.background("sending a uniqueness conflict to "+st, func(ctx context.Context) error {
				msg, err := c.Identity.Message(st, uniqueness.ConflictType, cf)
				if err != nil {
					return err
				}
				if err := c.Store.SaveSent(msg); err != nil {
					return err
				}
				return c.deliver(ctx, msg)
			})
		}
	}
	return nil
}

// Delivery and ledger

// Resend delivers a sent record again, for example after a network failure.
func (c *Commonwealth) Resend(ctx context.Context, id string) error {
	r, err := c.Store.Record(id)
	if err != nil {
		return err
	}
	if r.Direction != "sent" || r.Envelope.To == "" {
		return fmt.Errorf("commonwealth: record %s was not sent to an inbox", id)
	}
	return c.deliver(ctx, r.Envelope)
}

func (c *Commonwealth) logAndSend(ctx context.Context, env *record.Envelope) error {
	if _, err := c.Log.Append(env); err != nil {
		return fmt.Errorf("commonwealth: logging %s: %w", env.Type, err)
	}
	sendErr := c.deliver(ctx, env)
	if _, err := c.PublishLedger(ctx); err != nil && sendErr == nil {
		return err
	}
	return sendErr
}

func (c *Commonwealth) deliver(ctx context.Context, env *record.Envelope) error {
	rc, err := c.Sender.Send(ctx, env)
	switch {
	case rc != nil && rc.Status == protocol.StatusRejected:
		c.Store.SetDelivery(env.ID, "rejected: "+rc.Reason)
	case rc != nil:
		c.Store.SetDelivery(env.ID, rc.Status)
	}
	return err
}

// PublishLedger signs a checkpoint of the log and asks the witnesses to
// cosign it. It returns the number of cosignatures collected.
func (c *Commonwealth) PublishLedger(ctx context.Context) (int, error) {
	if _, err := c.Log.Checkpoint(); err != nil {
		return 0, err
	}
	if len(c.Witnesses.Witnesses) == 0 {
		return 0, nil
	}
	return c.Log.RequestCosignatures(ctx, c.Registry, c.HTTP, c.Witnesses.Witnesses)
}

// EntryStatus is the verification result for one ledger entry.
type EntryStatus struct {
	Index     uint64
	Envelope  *record.Envelope
	Signed    error     // nil if the signature verifies against the registry
	Witnessed time.Time // zero if not yet witnessed under the policy
	Evidence  error
}

// LedgerEntries returns the newest entries of the log, up to limit, each
// checked against the registry and the witness policy.
func (c *Commonwealth) LedgerEntries(limit int) ([]EntryStatus, error) {
	size, err := c.Log.Storage.Size()
	if err != nil {
		return nil, err
	}
	var out []EntryStatus
	for i := size; i > 0 && len(out) < limit; i-- {
		st, err := c.LedgerEntry(i - 1)
		if err != nil {
			return nil, err
		}
		out = append(out, *st)
	}
	return out, nil
}

// LedgerEntry returns one entry of the log, verified.
func (c *Commonwealth) LedgerEntry(index uint64) (*EntryStatus, error) {
	data, err := c.Log.Storage.Entry(index)
	if err != nil {
		return nil, err
	}
	env, err := record.Parse(data)
	if err != nil {
		return nil, err
	}
	st := &EntryStatus{Index: index, Envelope: env, Signed: env.VerifyWith(c.Registry)}
	ev, err := c.Log.Evidence(index)
	if err == nil {
		st.Witnessed, err = ledger.VerifyEvidence(c.Registry, ev, c.Witnesses)
	}
	st.Evidence = err
	return st, nil
}

// Summary describes a record's payload in a few words, for lists.
func Summary(env *record.Envelope) string {
	switch env.Type {
	case dividend.EligibilityCountType:
		if n, err := dividend.DecodeCount(env); err == nil {
			return fmt.Sprintf("%s: %d recipients, %d adults", n.Period, n.DividendRecipients, n.Adults)
		}
	case dividend.SettlementType:
		if d, err := dividend.DecodeSettlement(env); err == nil {
			return fmt.Sprintf("%s to %s: %s %s × %d = %s %s", d.Period, env.To, d.PerPerson, d.Unit, d.Recipients, d.Total, d.Unit)
		}
	case dividend.ConfirmationType:
		if n, err := dividend.DecodeConfirmation(env); err == nil {
			return fmt.Sprintf("%s paid %d recipients, %s %s", env.Issuer, n.PaidRecipients, n.PaidTotal, n.Unit)
		}
	case audit.RequestType:
		return "audit of " + env.To
	case audit.FindingType:
		if f, err := audit.DecodeFinding(env); err == nil {
			return fmt.Sprintf("%s: %d of %d sampled unverified; repayment %s %s", env.To, f.Unverified, f.Sampled, f.Repayment, f.Unit)
		}
	case registry.AttestationType:
		if a, err := registry.ParseAttestation(env); err == nil {
			return fmt.Sprintf("attested %s (%s), %d key(s)", a.Subject, a.SubjectLayer, len(a.Keys))
		}
	case uniqueness.ConfigType:
		var cfg uniqueness.Config
		if json.Unmarshal(env.Payload, &cfg) == nil {
			return fmt.Sprintf("uniqueness epoch %d: %d of %d operators", cfg.Epoch, len(cfg.Commitments), len(cfg.Operators))
		}
	}
	return strings.TrimSuffix(env.Type, "/1")
}
