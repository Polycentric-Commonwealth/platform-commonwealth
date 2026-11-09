package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/polycentric-commonwealth/foundation/amount"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"

	"github.com/polycentric-commonwealth/platform-commonwealth/internal/commonwealth"
	"github.com/polycentric-commonwealth/platform-commonwealth/internal/store"
)

// periodView is a Commons Fund period with its counts.
type periodView struct {
	store.Period
	Counts []countView
	Total  int64 // recipients counted so far
}

// countView is one State's part in a period.
type countView struct {
	store.Count
	Total               string // settlement total
	Status, StatusClass string
	Audit, AuditClass   string
	Resend              string
}

func (s *Server) periods() ([]periodView, error) {
	periods, err := s.Store.Periods()
	if err != nil {
		return nil, err
	}
	var out []periodView
	for _, p := range periods {
		pv := periodView{Period: p}
		counts, err := s.Store.Counts(p.Period)
		if err != nil {
			return nil, err
		}
		for _, c := range counts {
			cv := countView{Count: c}
			pv.Total += c.Recipients
			if c.Settlement != "" {
				cv.Total, _ = amountTimes(p.PerPerson, c.Recipients)
			}
			switch {
			case c.Confirmation != "":
				cv.Status, cv.StatusClass = "Paid and confirmed", "ok"
			case c.Settlement != "":
				rec, err := s.Store.Record(c.Settlement)
				if err != nil {
					return nil, err
				}
				switch {
				case rec.Delivery == "pending":
					cv.Status, cv.StatusClass, cv.Resend = "Settlement not yet delivered", "wait", c.Settlement
				case strings.HasPrefix(rec.Delivery, "rejected"):
					cv.Status, cv.StatusClass, cv.Resend = "Settlement refused by the State", "bad", c.Settlement
				default:
					cv.Status, cv.StatusClass = "Settled, awaiting payment", "wait"
				}
			default:
				cv.Status, cv.StatusClass = "Counted, awaiting settlement", "wait"
			}
			switch {
			case c.AuditRequest == "":
				cv.Audit = "Not audited"
			case c.AuditStatus == "requested":
				cv.Audit, cv.AuditClass = "Waiting for the State's answer", "wait"
			case c.AuditStatus == "checking":
				cv.Audit, cv.AuditClass = fmt.Sprintf("Checking %d sampled people", c.Sampled), "wait"
			case c.Unverified == 0:
				cv.Audit, cv.AuditClass = fmt.Sprintf("Passed: all %d sampled verified", c.Sampled), "ok"
			default:
				cv.Audit, cv.AuditClass = fmt.Sprintf("%d of %d sampled not found", c.Unverified, c.Sampled), "bad"
			}
			pv.Counts = append(pv.Counts, cv)
		}
		out = append(out, pv)
	}
	return out, nil
}

func amountTimes(perPerson string, n int64) (string, error) {
	return amount.MulInt(perPerson, n)
}

type checkpointView struct {
	Size      uint64
	IssuedAt  string
	Witnesses []witnessView
}

type witnessView struct{ Instance, At string }

func (s *Server) checkpoint() *checkpointView {
	cp, cosigs, ok := s.CW.Log.Latest()
	if !ok {
		return nil
	}
	var payload ledger.Checkpoint
	if err := json.Unmarshal(cp.Payload, &payload); err != nil {
		return nil
	}
	v := &checkpointView{Size: payload.Size, IssuedAt: cp.IssuedAt}
	for _, c := range cosigs {
		v.Witnesses = append(v.Witnesses, witnessView{Instance: c.Issuer, At: c.IssuedAt})
	}
	return v
}

// --- Public pages ------------------------------------------------------------

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	v := s.newView(r, "Overview", "overview")
	members, err := s.Store.Members()
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, m := range members {
		if m.Status != "active" {
			continue
		}
		if m.Layer == "state" {
			v.StateCount++
		} else {
			v.RegionCount++
		}
	}
	periods, err := s.Store.Periods()
	if err != nil {
		s.fail(w, err)
		return
	}
	for i := range periods {
		if periods[i].Status == "settled" {
			v.Latest = &periods[i]
			break
		}
	}
	if v.LedgerSize, err = s.CW.Log.Storage.Size(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "overview", v)
}

func (s *Server) members(w http.ResponseWriter, r *http.Request) {
	v := s.newView(r, "Members", "members")
	var err error
	if v.Members, err = s.Store.Members(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "members", v)
}

func (s *Server) dividends(w http.ResponseWriter, r *http.Request) {
	v := s.newView(r, "Dividends", "dividends")
	var err error
	if v.Periods, err = s.periods(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "dividends", v)
}

func (s *Server) audits(w http.ResponseWriter, r *http.Request) {
	v := s.newView(r, "Audits", "audits")
	var err error
	if v.Audits, err = s.Store.Audits(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "audits", v)
}

func (s *Server) uniquenessView(r *http.Request, title, section string) (*view, error) {
	v := s.newView(r, title, section)
	env, cfg, err := s.CW.UniquenessConfig()
	if errors.Is(err, store.ErrNotFound) {
		return v, nil
	} else if err != nil {
		return nil, err
	}
	v.ConfigRecord, v.Config = env, cfg
	v.Uniqueness, err = s.Store.Uniqueness(cfg.Epoch)
	return v, err
}

func (s *Server) uniquenessPage(w http.ResponseWriter, r *http.Request) {
	v, err := s.uniquenessView(r, "Uniqueness", "uniqueness")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "uniqueness", v)
}

func (s *Server) ledgerPage(w http.ResponseWriter, r *http.Request) {
	v := s.newView(r, "Public ledger", "ledger")
	var err error
	if v.Entries, err = s.CW.LedgerEntries(200); err != nil {
		s.fail(w, err)
		return
	}
	v.Checkpoint = s.checkpoint()
	s.render(w, http.StatusOK, "ledger", v)
}

func (s *Server) entryPage(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.ParseUint(r.PathValue("index"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	entry, err := s.CW.LedgerEntry(index)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	v := s.newView(r, fmt.Sprintf("Record %d", index), "ledger")
	v.Entry = entry
	v.Hash = ledger.EncodeHash(entryHash(entry.Envelope))
	data, _ := json.MarshalIndent(entry.Envelope, "", "  ")
	v.JSON = string(data)
	s.render(w, http.StatusOK, "entry", v)
}

// --- Commons Fund ------------------------------------------------------------

func (s *Server) fundView(r *http.Request) (*view, error) {
	v := s.newView(r, "Commons Fund", "officials-fund")
	var err error
	v.Periods, err = s.periods()
	return v, err
}

func (s *Server) fund(w http.ResponseWriter, r *http.Request) {
	v, err := s.fundView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "officials-fund", v)
}

func (s *Server) fundError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	v, err := s.fundView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	v.Error = msg
	s.render(w, status, "officials-fund", v)
}

func (s *Server) settle(w http.ResponseWriter, r *http.Request) {
	period, pool := r.PathValue("period"), strings.TrimSpace(r.PostFormValue("pool"))
	per, err := s.CW.SettlePeriod(r.Context(), period, pool, me(r).Username)
	switch {
	case per == "" && err != nil:
		s.fundError(w, r, http.StatusUnprocessableEntity, "The period was not settled: "+err.Error())
		return
	case err != nil:
		s.logAction(r, "settled period", fmt.Sprintf("%s: pool %s XCU, %s per person", period, pool, per))
		s.fundError(w, r, http.StatusBadGateway, "The period is settled, but not every settlement was delivered. Send them again from the table: "+err.Error())
		return
	}
	s.logAction(r, "settled period", fmt.Sprintf("%s: pool %s XCU, %s per person", period, pool, per))
	http.Redirect(w, r, "/officials?done=settled", http.StatusSeeOther)
}

func (s *Server) resend(w http.ResponseWriter, r *http.Request) {
	if err := s.CW.Resend(r.Context(), r.PathValue("id")); err != nil {
		msg := "The record could not be delivered: " + err.Error()
		if _, rejected := protocol.IsRejected(err); rejected {
			msg = "The recipient refused the record: " + err.Error()
		}
		s.fundError(w, r, http.StatusBadGateway, msg)
		return
	}
	s.logAction(r, "resent record", r.PathValue("id"))
	http.Redirect(w, r, "/officials?done=resent", http.StatusSeeOther)
}

// --- Members -----------------------------------------------------------------

func (s *Server) membersView(r *http.Request) (*view, error) {
	v := s.newView(r, "Members", "officials-members")
	var err error
	v.Members, err = s.Store.Members()
	return v, err
}

func (s *Server) officialsMembers(w http.ResponseWriter, r *http.Request) {
	v, err := s.membersView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "officials-members", v)
}

func (s *Server) membersError(w http.ResponseWriter, r *http.Request, msg, pasted string) {
	v, err := s.membersView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	v.Error, v.ReviewJSON = msg, pasted
	s.render(w, http.StatusUnprocessableEntity, "officials-members", v)
}

// reviewMember shows what a pasted description says, so the official can
// confirm the keys with the member before attesting.
func (s *Server) reviewMember(w http.ResponseWriter, r *http.Request) {
	pasted := strings.TrimSpace(r.PostFormValue("description"))
	env, err := record.Parse([]byte(pasted))
	if err != nil {
		s.membersError(w, r, "That is not a signed record: "+err.Error(), pasted)
		return
	}
	d, err := registry.ParseDescription(env)
	if err != nil {
		s.membersError(w, r, "That is not an instance description: "+err.Error(), pasted)
		return
	}
	v, err := s.membersView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	v.Review, v.ReviewJSON = d, pasted
	if d.Parent != s.CW.Identity.Instance {
		v.Error = fmt.Sprintf("%s names %q as its parent, so its parent must attest it, not this Commonwealth.", d.Instance, d.Parent)
	}
	s.render(w, http.StatusOK, "officials-members", v)
}

func (s *Server) attestMember(w http.ResponseWriter, r *http.Request) {
	pasted := strings.TrimSpace(r.PostFormValue("description"))
	if r.PostFormValue("confirmed") != "yes" {
		s.membersError(w, r, "Confirm that you checked the key fingerprints with the member.", pasted)
		return
	}
	att, err := s.CW.AttestMember(r.Context(), []byte(pasted), me(r).Username)
	if err != nil && att == nil {
		s.membersError(w, r, "The member was not attested: "+err.Error(), pasted)
		return
	}
	s.logAction(r, "attested member", commonwealth.Summary(att))
	v, verr := s.membersView(r)
	if verr != nil {
		s.fail(w, verr)
		return
	}
	data, _ := att.Marshal()
	v.Attestation = string(data)
	v.Notice = "Attested. Give the member this attestation; they add it with pcstate attestation add, or download it from the members table."
	if err != nil {
		v.Error = "The attestation was logged, but the ledger checkpoint was not fully cosigned: " + err.Error()
	}
	s.render(w, http.StatusOK, "officials-members", v)
}

func (s *Server) memberStatus(w http.ResponseWriter, r *http.Request) {
	instance, status := r.PathValue("instance"), r.PostFormValue("status")
	if err := s.Store.SetMemberStatus(instance, status); errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.membersError(w, r, err.Error(), "")
		return
	}
	s.logAction(r, "set member status", instance+" to "+status)
	http.Redirect(w, r, "/officials/members?done=status", http.StatusSeeOther)
}

func (s *Server) attestationFile(w http.ResponseWriter, r *http.Request) {
	m, err := s.Store.Member(r.PathValue("instance"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	rec, err := s.Store.Record(m.Attestation)
	if err != nil {
		s.fail(w, err)
		return
	}
	data, _ := rec.Envelope.Marshal()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-attestation.json"`, m.Instance))
	w.Write(data)
}

// --- Audit Office ------------------------------------------------------------

func (s *Server) officialsAudits(w http.ResponseWriter, r *http.Request) {
	v := s.newView(r, "Audit Office", "officials-audits")
	var err error
	if v.Audits, err = s.Store.Audits(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "officials-audits", v)
}

func (s *Server) auditView(r *http.Request) (*view, error) {
	a, err := s.Store.Audit(r.PathValue("request"))
	if err != nil {
		return nil, err
	}
	v := s.newView(r, "Audit of "+a.State+", "+a.Period, "officials-audits")
	v.Audit = a
	v.Openings, err = s.Store.Openings(a.Request)
	return v, err
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	v, err := s.auditView(r)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "officials-audit", v)
}

func (s *Server) auditError(w http.ResponseWriter, r *http.Request, msg string) {
	v, err := s.auditView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	v.Error = msg
	s.render(w, http.StatusUnprocessableEntity, "officials-audit", v)
}

func (s *Server) fieldCheck(w http.ResponseWriter, r *http.Request) {
	request := r.PathValue("request")
	pos, err := strconv.ParseUint(r.PostFormValue("position"), 10, 64)
	result := r.PostFormValue("result")
	if err != nil || (result != "found" && result != "not-found") {
		s.auditError(w, r, "Choose found or not found for a sampled person.")
		return
	}
	if err := s.Store.RecordFieldCheck(request, pos, result == "found", me(r).Username); err != nil {
		s.auditError(w, r, "The check was not recorded: the audit is not open for field checks.")
		return
	}
	s.logAction(r, "recorded field check", fmt.Sprintf("audit %s, position %d: %s", request, pos, result))
	http.Redirect(w, r, "/officials/audits/"+request+"?done=checked#p"+strconv.FormatUint(pos, 10), http.StatusSeeOther)
}

func (s *Server) issueFinding(w http.ResponseWriter, r *http.Request) {
	request := r.PathValue("request")
	f, err := s.CW.IssueFinding(r.Context(), request, me(r).Username)
	if f == nil && err != nil {
		s.auditError(w, r, "The finding was not issued: "+strings.TrimPrefix(err.Error(), "commonwealth: "))
		return
	}
	s.logAction(r, "issued audit finding", fmt.Sprintf("audit %s: %d of %d unverified, repayment %s %s", request, f.Unverified, f.Sampled, f.Repayment, f.Unit))
	if err != nil {
		s.auditError(w, r, "The finding was issued and logged, but not delivered. Send it again from the Commons Fund page: "+err.Error())
		return
	}
	http.Redirect(w, r, "/officials/audits/"+request+"?done=finding", http.StatusSeeOther)
}

// --- Ledger ------------------------------------------------------------------

func (s *Server) officialsLedger(w http.ResponseWriter, r *http.Request) {
	v := s.newView(r, "Ledger", "officials-ledger")
	v.Checkpoint = s.checkpoint()
	v.WitnessCount = len(s.CW.Witnesses.Witnesses)
	s.render(w, http.StatusOK, "officials-ledger", v)
}

func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	s.logAction(r, "published checkpoint", "")
	if _, err := s.CW.PublishLedger(r.Context()); err != nil {
		v := s.newView(r, "Ledger", "officials-ledger")
		v.Checkpoint = s.checkpoint()
		v.WitnessCount = len(s.CW.Witnesses.Witnesses)
		v.Error = "The checkpoint was published, but not every witness cosigned it: " + err.Error()
		s.render(w, http.StatusBadGateway, "officials-ledger", v)
		return
	}
	http.Redirect(w, r, "/officials/ledger?done=published", http.StatusSeeOther)
}

// --- Officials' accounts -----------------------------------------------------

func (s *Server) teamView(r *http.Request) (*view, error) {
	v := s.newView(r, "Officials", "officials-team")
	v.Roles = store.Roles
	var err error
	if v.Officials, err = s.Store.Officials(); err != nil {
		return nil, err
	}
	v.ActionLog, err = s.Store.Actions(100)
	return v, err
}

func (s *Server) team(w http.ResponseWriter, r *http.Request) {
	v, err := s.teamView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "officials-team", v)
}

// teamResult shows the team page with a message, and a new password once if
// one was just set.
func (s *Server) teamResult(w http.ResponseWriter, r *http.Request, status int, notice, problem, username, password string) {
	v, err := s.teamView(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	v.Notice, v.Error, v.NewUsername, v.NewPassword = notice, problem, username, password
	s.render(w, status, "officials-team", v)
}

func (s *Server) addOfficial(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(strings.ToLower(r.PostFormValue("username")))
	password, err := store.GeneratePassword()
	if err != nil {
		s.fail(w, err)
		return
	}
	err = s.Store.AddOfficial(username, r.PostFormValue("name"), r.PostFormValue("role"), password)
	if errors.Is(err, store.ErrInvalidOfficial) {
		s.teamResult(w, r, http.StatusUnprocessableEntity, "", "The account was not created: "+strings.TrimPrefix(err.Error(), store.ErrInvalidOfficial.Error()+": ")+".", "", "")
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	s.logAction(r, "added official", username+" as "+r.PostFormValue("role"))
	s.teamResult(w, r, http.StatusOK, "Account created.", "", username, password)
}

func (s *Server) resetOfficial(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	password, err := store.GeneratePassword()
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.SetPassword(username, password); errors.Is(err, store.ErrNotFound) {
		http.Error(w, "No such official.", http.StatusNotFound)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.SetDisabled(username, false); err != nil {
		s.fail(w, err)
		return
	}
	s.logAction(r, "reset password", username)
	if username == me(r).Username {
		// Resetting your own password signs you out everywhere, here too.
		http.Redirect(w, r, "/officials/login", http.StatusSeeOther)
		return
	}
	s.teamResult(w, r, http.StatusOK, "Password reset. The official has been signed out everywhere.", "", username, password)
}

func (s *Server) disableOfficial(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == me(r).Username {
		s.teamResult(w, r, http.StatusUnprocessableEntity, "", "You cannot disable your own account. Ask another admin.", "", "")
		return
	}
	if err := s.Store.SetDisabled(username, true); errors.Is(err, store.ErrNotFound) {
		http.Error(w, "No such official.", http.StatusNotFound)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	s.logAction(r, "disabled official", username)
	s.teamResult(w, r, http.StatusOK, "Account disabled and signed out everywhere. Reset its password to enable it again.", "", "", "")
}
