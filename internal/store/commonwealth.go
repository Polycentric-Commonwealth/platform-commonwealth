package store

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/polycentric-commonwealth/foundation/audit"
	"github.com/polycentric-commonwealth/foundation/dividend"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/uniqueness"
)

// Errors for the Commonwealth's flows.
var (
	ErrPeriodSettled  = errors.New("store: the period has already been settled")
	ErrDuplicateCount = errors.New("store: a count for this period was already accepted from this State")
	ErrAuditState     = errors.New("store: the audit is not at the right stage for this")
)

// Member is an attested Region or State.
type Member struct {
	Instance    string
	Layer       string
	Name        string
	Description *record.Envelope
	Attestation string
	AttestedAt  string
	AttestedBy  string
	Status      string
}

// SaveMember records an attestation of a member, replacing an earlier one
// (for example after a key rotation).
func (s *Store) SaveMember(desc, attestation *record.Envelope, layer, name, actor string) error {
	body, err := desc.Marshal()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertRecord(tx, attestation, "sent", desc.Issuer, false); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE records SET delivery = 'handed over' WHERE id = ?`, attestation.ID); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO members (instance, layer, name, description, attestation, attested_at, attested_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (instance) DO UPDATE SET layer = excluded.layer, name = excluded.name, description = excluded.description,
			attestation = excluded.attestation, attested_at = excluded.attested_at, attested_by = excluded.attested_by`,
		desc.Issuer, layer, name, body, attestation.ID, now(), actor)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SetMemberStatus suspends or reinstates a member.
func (s *Store) SetMemberStatus(instance, status string) error {
	if status != "active" && status != "suspended" {
		return fmt.Errorf("store: status must be active or suspended")
	}
	res, err := s.db.Exec(`UPDATE members SET status = ? WHERE instance = ?`, status, instance)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Member returns one member.
func (s *Store) Member(instance string) (*Member, error) {
	list, err := s.members(`WHERE instance = ?`, instance)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// Members lists every member, Regions first, then by name.
func (s *Store) Members() ([]Member, error) {
	return s.members(`ORDER BY layer, name`)
}

func (s *Store) members(where string, args ...any) ([]Member, error) {
	rows, err := s.db.Query(`SELECT instance, layer, name, description, attestation, attested_at, attested_by, status FROM members `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		var body []byte
		if err := rows.Scan(&m.Instance, &m.Layer, &m.Name, &body, &m.Attestation, &m.AttestedAt, &m.AttestedBy, &m.Status); err != nil {
			return nil, err
		}
		if m.Description, err = record.Parse(body); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Period is a Commons Fund period.
type Period struct {
	Period     string
	Status     string
	Pool       string
	PerPerson  string
	Recipients int64
	PaidOut    string
	SettledAt  string
	SettledBy  string
	Counts     int
}

// Count is an accepted eligibility count with its progress.
type Count struct {
	Record       string
	Period       string
	State        string
	Residents    int64
	Adults       int64
	Recipients   int64
	Settlement   string
	Confirmation string
	AuditRequest string
	AuditStatus  string
	Sampled      int
	Unverified   int
	Finding      string
}

// SaveCount stores an accepted eligibility count, opening its period if
// needed. It fails if the period is settled or the State already reported.
func (s *Store) SaveCount(env *record.Envelope, c *dividend.EligibilityCount) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO periods (period) VALUES (?)`, c.Period); err != nil {
		return err
	}
	var status string
	if err := tx.QueryRow(`SELECT status FROM periods WHERE period = ?`, c.Period).Scan(&status); err != nil {
		return err
	}
	if status != "open" {
		return ErrPeriodSettled
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM counts WHERE period = ? AND state = ?`, c.Period, env.Issuer).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrDuplicateCount
	}
	if err := insertRecord(tx, env, "received", env.Issuer, true); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO counts (record, period, state, residents, adults, recipients) VALUES (?, ?, ?, ?, ?, ?)`,
		env.ID, c.Period, env.Issuer, c.Residents, c.Adults, c.DividendRecipients); err != nil {
		return err
	}
	return tx.Commit()
}

const countColumns = `c.record, c.period, c.state, c.residents, c.adults, c.recipients, IFNULL(c.settlement, ''), IFNULL(c.confirmation, ''),
	IFNULL(a.request, ''), IFNULL(a.status, ''), IFNULL(a.sampled, 0), IFNULL(a.unverified, 0), IFNULL(a.finding, '')`

func scanCounts(rows *sql.Rows) ([]Count, error) {
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Record, &c.Period, &c.State, &c.Residents, &c.Adults, &c.Recipients, &c.Settlement, &c.Confirmation,
			&c.AuditRequest, &c.AuditStatus, &c.Sampled, &c.Unverified, &c.Finding); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Counts lists the counts of a period, by State.
func (s *Store) Counts(period string) ([]Count, error) {
	rows, err := s.db.Query(`SELECT `+countColumns+` FROM counts c LEFT JOIN audits a ON a.count = c.record WHERE c.period = ? ORDER BY c.state`, period)
	if err != nil {
		return nil, err
	}
	return scanCounts(rows)
}

// CountByRecord returns a count by its record id.
func (s *Store) CountByRecord(id string) (*Count, error) {
	rows, err := s.db.Query(`SELECT `+countColumns+` FROM counts c LEFT JOIN audits a ON a.count = c.record WHERE c.record = ?`, id)
	if err != nil {
		return nil, err
	}
	list, err := scanCounts(rows)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// CountBySettlement returns the count a settlement was based on.
func (s *Store) CountBySettlement(id string) (*Count, error) {
	var rec string
	if err := s.db.QueryRow(`SELECT record FROM counts WHERE settlement = ?`, id).Scan(&rec); err != nil {
		return nil, notFound(err)
	}
	return s.CountByRecord(rec)
}

// Periods lists every period, newest first.
func (s *Store) Periods() ([]Period, error) {
	rows, err := s.db.Query(`SELECT p.period, p.status, p.pool, p.per_person, p.recipients, p.paid_out, p.settled_at, p.settled_by,
		(SELECT COUNT(*) FROM counts c WHERE c.period = p.period) FROM periods p ORDER BY p.period DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Period
	for rows.Next() {
		var p Period
		if err := rows.Scan(&p.Period, &p.Status, &p.Pool, &p.PerPerson, &p.Recipients, &p.PaidOut, &p.SettledAt, &p.SettledBy, &p.Counts); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SettlePeriod records a period's settlement: the pool, the per-person
// dividend, and one settlement record for each count. It fails if the
// period was settled already.
func (s *Store) SettlePeriod(period, pool, perPerson, paidOut string, recipients int64, actor string, settlements map[string]*record.Envelope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE periods SET status = 'settled', pool = ?, per_person = ?, recipients = ?, paid_out = ?, settled_at = ?, settled_by = ?
		WHERE period = ? AND status = 'open'`, pool, perPerson, recipients, paidOut, now(), actor, period)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPeriodSettled
	}
	for countID, env := range settlements {
		if err := insertRecord(tx, env, "sent", env.To, false); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE counts SET settlement = ? WHERE record = ?`, env.ID, countID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SaveConfirmation stores a State's confirmation of a settlement.
func (s *Store) SaveConfirmation(env *record.Envelope, settlement string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertRecord(tx, env, "received", env.Issuer, true); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE counts SET confirmation = ? WHERE settlement = ? AND confirmation IS NULL`, env.ID, settlement)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: settlement %s is unknown or already confirmed", settlement)
	}
	return tx.Commit()
}

// Audit is an eligibility audit and its progress.
type Audit struct {
	Request     string
	Count       string
	State       string
	Period      string
	Recipients  int64
	Status      string
	Sampled     int
	Unverified  int
	RespondedAt string
	Finding     string
	IssuedBy    string
	Pending     int // valid openings not yet checked in the field
}

// Opening is one sampled entry of an audit. Ref, Name and BirthDate are
// empty once the finding is issued.
type Opening struct {
	Position  uint64
	Valid     bool
	Problem   string
	Ref       string
	Name      string
	BirthDate string
	Field     string
	CheckedBy string
	CheckedAt string
}

// SaveAuditRequest stores a sent audit request.
func (s *Store) SaveAuditRequest(env *record.Envelope, count string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertRecord(tx, env, "sent", env.To, false); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO audits (request, count, state) VALUES (?, ?, ?)`, env.ID, count, env.To); err != nil {
		return err
	}
	return tx.Commit()
}

// SaveAuditResults stores the checked openings of a State's response. The
// response itself is not kept.
func (s *Store) SaveAuditResults(request string, results []audit.Result) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE audits SET status = 'checking', sampled = ?, responded_at = ? WHERE request = ? AND status = 'requested'`,
		len(results), now(), request)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAuditState
	}
	for _, r := range results {
		var ref, name, born string
		if r.Opening != nil && r.Valid {
			ref, name, born = r.Opening.Ref, r.Opening.Name, r.Opening.BirthDate
		}
		if _, err := tx.Exec(`INSERT INTO audit_openings (request, position, valid, problem, ref, name, birth_date) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			request, r.Index, r.Valid, r.Problem, ref, name, born); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const auditColumns = `a.request, a.count, a.state, c.period, c.recipients, a.status, a.sampled, a.unverified, a.responded_at, IFNULL(a.finding, ''), a.issued_by,
	(SELECT COUNT(*) FROM audit_openings o WHERE o.request = a.request AND o.valid = 1 AND o.field = '')`

func (s *Store) audits(where string, args ...any) ([]Audit, error) {
	rows, err := s.db.Query(`SELECT `+auditColumns+` FROM audits a JOIN counts c ON c.record = a.count `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var a Audit
		if err := rows.Scan(&a.Request, &a.Count, &a.State, &a.Period, &a.Recipients, &a.Status, &a.Sampled, &a.Unverified,
			&a.RespondedAt, &a.Finding, &a.IssuedBy, &a.Pending); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Audits lists every audit, newest period first.
func (s *Store) Audits() ([]Audit, error) {
	return s.audits(`ORDER BY c.period DESC, a.state`)
}

// Audit returns one audit by its request id.
func (s *Store) Audit(request string) (*Audit, error) {
	list, err := s.audits(`WHERE a.request = ?`, request)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// Openings returns an audit's sampled entries, by position.
func (s *Store) Openings(request string) ([]Opening, error) {
	rows, err := s.db.Query(`SELECT position, valid, problem, ref, name, birth_date, field, checked_by, checked_at
		FROM audit_openings WHERE request = ? ORDER BY position`, request)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Opening
	for rows.Next() {
		var o Opening
		if err := rows.Scan(&o.Position, &o.Valid, &o.Problem, &o.Ref, &o.Name, &o.BirthDate, &o.Field, &o.CheckedBy, &o.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// RecordFieldCheck records whether auditors found a sampled person.
func (s *Store) RecordFieldCheck(request string, position uint64, found bool, actor string) error {
	result := "not-found"
	if found {
		result = "found"
	}
	res, err := s.db.Exec(`UPDATE audit_openings SET field = ?, checked_by = ?, checked_at = ?
		WHERE request = ? AND position = ? AND valid = 1
		AND (SELECT status FROM audits WHERE request = ?) = 'checking'`, result, actor, now(), request, position, request)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAuditState
	}
	return nil
}

// FinishAudit stores the finding and erases the sampled people's details.
func (s *Store) FinishAudit(request string, unverified int, finding *record.Envelope, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertRecord(tx, finding, "sent", finding.To, false); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE audits SET status = 'finding', unverified = ?, finding = ?, issued_by = ? WHERE request = ? AND status = 'checking'`,
		unverified, finding.ID, actor, request)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAuditState
	}
	if _, err := tx.Exec(`UPDATE audit_openings SET ref = '', name = '', birth_date = '' WHERE request = ?`, request); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplyRegistration records a State's uniqueness registration and returns
// the conflicts it creates or changes: one for each added token that
// another State holds too.
func (s *Store) ApplyRegistration(state string, r *uniqueness.Registration) ([]uniqueness.Conflict, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	holders := func(token string) ([]string, error) {
		rows, err := tx.Query(`SELECT state FROM uniqueness_tokens WHERE epoch = ? AND token = ? ORDER BY state`, r.Epoch, token)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var st string
			if err := rows.Scan(&st); err != nil {
				return nil, err
			}
			out = append(out, st)
		}
		return out, rows.Err()
	}
	for _, t := range r.Remove {
		if _, err := tx.Exec(`DELETE FROM uniqueness_tokens WHERE epoch = ? AND token = ? AND state = ?`, r.Epoch, t, state); err != nil {
			return nil, err
		}
		h, err := holders(t)
		if err != nil {
			return nil, err
		}
		if len(h) < 2 {
			if _, err := tx.Exec(`DELETE FROM uniqueness_conflicts WHERE epoch = ? AND token = ?`, r.Epoch, t); err != nil {
				return nil, err
			}
		} else if _, err := tx.Exec(`UPDATE uniqueness_conflicts SET states = ? WHERE epoch = ? AND token = ?`, strings.Join(h, ","), r.Epoch, t); err != nil {
			return nil, err
		}
	}
	var conflicts []uniqueness.Conflict
	for _, t := range r.Add {
		res, err := tx.Exec(`INSERT OR IGNORE INTO uniqueness_tokens (epoch, token, state) VALUES (?, ?, ?)`, r.Epoch, t, state)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		h, err := holders(t)
		if err != nil {
			return nil, err
		}
		if len(h) > 1 {
			if _, err := tx.Exec(`INSERT INTO uniqueness_conflicts (epoch, token, states, opened_at) VALUES (?, ?, ?, ?)
				ON CONFLICT (epoch, token) DO UPDATE SET states = excluded.states`, r.Epoch, t, strings.Join(h, ","), now()); err != nil {
				return nil, err
			}
			conflicts = append(conflicts, uniqueness.Conflict{Epoch: r.Epoch, Token: t, States: slices.Clone(h)})
		}
	}
	return conflicts, tx.Commit()
}

// UniquenessSummary counts registered tokens and open conflicts per State
// for an epoch.
type UniquenessSummary struct {
	State     string
	Tokens    int
	Conflicts int
}

// Uniqueness returns the registry's summary for an epoch, by State.
func (s *Store) Uniqueness(epoch int64) ([]UniquenessSummary, error) {
	rows, err := s.db.Query(`SELECT t.state, COUNT(*),
		(SELECT COUNT(*) FROM uniqueness_conflicts c WHERE c.epoch = t.epoch AND (',' || c.states || ',') LIKE ('%,' || t.state || ',%'))
		FROM uniqueness_tokens t WHERE t.epoch = ? GROUP BY t.state ORDER BY t.state`, epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UniquenessSummary
	for rows.Next() {
		var u UniquenessSummary
		if err := rows.Scan(&u.State, &u.Tokens, &u.Conflicts); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetSetting stores a small named value.
func (s *Store) SetSetting(key string, value []byte) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Setting returns a named value.
func (s *Store) Setting(key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v, notFound(err)
}
