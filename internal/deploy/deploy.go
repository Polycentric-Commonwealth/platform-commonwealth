// Package deploy runs the Commonwealth platform as a long-lived
// deployment: its configuration, signing key, description and database live
// in one directory, and it keeps its members' descriptions fresh by
// discovery.
//
// The directory holds:
//
//	pccommonwealth.json  configuration (see Config)
//	keys/<id>.key        the signing key's seed, unpadded base64url, mode 0600
//	description.json     the Commonwealth's signed instance description
//	commonwealth.db      the database
package deploy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/polycentric-commonwealth/foundation/amount"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"

	"github.com/polycentric-commonwealth/platform-commonwealth/internal/commonwealth"
	"github.com/polycentric-commonwealth/platform-commonwealth/internal/store"
	"github.com/polycentric-commonwealth/platform-commonwealth/internal/web"
)

// File names inside a deployment directory.
const (
	ConfigFile      = "pccommonwealth.json"
	DescriptionFile = "description.json"
	DatabaseFile    = "commonwealth.db"
	KeysDir         = "keys"
)

// Config is a deployment's configuration, kept in pccommonwealth.json.
type Config struct {
	// Instance is the Commonwealth's instance identifier, a domain name.
	Instance string `json:"instance"`
	// Name is its human-readable name.
	Name string `json:"name"`
	// BaseURL is the public https URL of this platform; the protocol is
	// served under BaseURL + "pc/".
	BaseURL string `json:"base_url"`
	// Listen is the address to serve on, such as ":8443".
	Listen string `json:"listen"`
	// TLSCert and TLSKey, if set, make the platform serve HTTPS itself.
	TLSCert string `json:"tls_cert,omitempty"`
	TLSKey  string `json:"tls_key,omitempty"`

	// Witnesses cosign the Commonwealth's ledger checkpoints: normally
	// member instances. The list may start empty and grow.
	Witnesses        []string `json:"witnesses"`
	WitnessThreshold int      `json:"witness_threshold"`

	// Multiplier applies to audit repayments, as a decimal string.
	Multiplier string `json:"multiplier,omitempty"`

	// Peers maps instances to the origin they are reached at, when that is
	// not https://<instance>.
	Peers map[string]string `json:"peers,omitempty"`

	// CAFile, if set, names PEM certificates trusted for peers in addition
	// to the system's roots.
	CAFile string `json:"ca_file,omitempty"`

	// KeyID is the current signing key's identifier.
	KeyID string `json:"key_id"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if !record.ValidInstanceID(c.Instance) {
		return fmt.Errorf("deploy: instance must be an instance identifier (a lowercase domain name), got %q", c.Instance)
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("deploy: name is required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || !strings.HasSuffix(u.Path, "/") {
		return fmt.Errorf("deploy: base_url must be an https URL ending in /, got %q", c.BaseURL)
	}
	if c.Listen == "" {
		return errors.New("deploy: listen is required")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("deploy: set both tls_cert and tls_key, or neither")
	}
	if c.WitnessThreshold < 0 || c.WitnessThreshold > len(c.Witnesses) || (len(c.Witnesses) > 0 && c.WitnessThreshold == 0) {
		return errors.New("deploy: witness_threshold must be between 1 and the number of witnesses (0 with no witnesses)")
	}
	for _, w := range c.Witnesses {
		if !record.ValidInstanceID(w) {
			return fmt.Errorf("deploy: witness %q is not an instance identifier", w)
		}
	}
	if c.Multiplier != "" {
		if _, err := amount.Parse(c.Multiplier); err != nil {
			return fmt.Errorf("deploy: multiplier: %w", err)
		}
	}
	for id, origin := range c.Peers {
		if u, err := url.Parse(origin); err != nil || u.Scheme != "https" || u.Host == "" || !record.ValidInstanceID(id) {
			return fmt.Errorf("deploy: peer %s must map to an https origin, got %q", id, origin)
		}
	}
	if c.KeyID == "" {
		return errors.New("deploy: key_id is required")
	}
	return nil
}

// Init creates a deployment directory with a new signing key, a signed
// description and an empty database. It returns the trust anchor members
// pin, in the form instance=ed25519:key.
func Init(dir string, cfg Config) (anchor string, err error) {
	if cfg.KeyID == "" {
		cfg.KeyID = "k1"
	}
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, ConfigFile)); err == nil {
		return "", fmt.Errorf("deploy: %s already holds a deployment", dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, KeysDir), 0o700); err != nil {
		return "", err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	if err := writeNew(filepath.Join(dir, KeysDir, cfg.KeyID+".key"), []byte(base64.RawURLEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return "", err
	}
	env, err := registry.NewDescription(&registry.Description{
		Instance: cfg.Instance, Layer: record.Commonwealth, Name: cfg.Name,
		Endpoints: map[string]string{"base": cfg.BaseURL + "pc/"},
		Keys: []registry.Key{{ID: cfg.KeyID, PublicKey: registry.EncodePublicKey(pub),
			ValidFrom: time.Now().UTC().Add(-time.Minute).Truncate(time.Second).Format(time.RFC3339)}},
	}, cfg.KeyID, priv)
	if err != nil {
		return "", err
	}
	data, err := env.Marshal()
	if err != nil {
		return "", err
	}
	if err := writeNew(filepath.Join(dir, DescriptionFile), data, 0o644); err != nil {
		return "", err
	}
	db, err := store.Open(filepath.Join(dir, DatabaseFile))
	if err != nil {
		return "", err
	}
	db.Close()
	if err := os.Chmod(filepath.Join(dir, DatabaseFile), 0o600); err != nil {
		return "", err
	}
	if err := saveJSON(filepath.Join(dir, ConfigFile), cfg, true); err != nil {
		return "", err
	}
	return cfg.Instance + "=" + registry.EncodePublicKey(pub), nil
}

// LoadConfig reads a deployment's configuration.
func LoadConfig(dir string) (*Config, error) {
	data, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		return nil, fmt.Errorf("deploy: %w (run pccommonwealth init first)", err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("deploy: %s: %w", ConfigFile, err)
	}
	return &cfg, cfg.Validate()
}

// OpenStore opens a deployment's database, for command-line tools.
func OpenStore(dir string) (*store.Store, error) {
	if _, err := LoadConfig(dir); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dir, DatabaseFile))
}

// Anchor returns the deployment's trust anchor, instance=ed25519:key.
func Anchor(dir string) (string, error) {
	desc, err := readRecord(filepath.Join(dir, DescriptionFile))
	if err != nil {
		return "", err
	}
	d, err := registry.ParseDescription(desc)
	if err != nil {
		return "", err
	}
	k, _ := d.Key(desc.Key)
	return d.Instance + "=" + k.PublicKey, nil
}

// Instance is an opened deployment.
type Instance struct {
	Config  *Config
	Dir     string
	CW      *commonwealth.Commonwealth
	Store   *store.Store
	Fetcher *registry.Fetcher
	HTTP    *http.Client

	// Logf reports background problems; it defaults to log.Printf.
	Logf func(format string, args ...any)

	mu        sync.Mutex
	refreshed bool
}

// Open loads a deployment and restores its members into the registry. It
// does not contact other instances; Refresh and Run do.
func Open(dir string) (*Instance, error) {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, KeysDir, cfg.KeyID+".key")
	if info, err := os.Stat(keyPath); err == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("deploy: key file for %s must not be readable by others (chmod 600)", cfg.KeyID)
	}
	seed, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(seed)))
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("deploy: key file for %s is not valid", cfg.KeyID)
	}
	priv := ed25519.NewKeyFromSeed(raw)
	desc, err := readRecord(filepath.Join(dir, DescriptionFile))
	if err != nil {
		return nil, err
	}
	client, err := httpClient(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	reg, err := registry.New(registry.Anchor{Instance: cfg.Instance, PublicKey: registry.EncodePublicKey(priv.Public().(ed25519.PublicKey))})
	if err != nil {
		return nil, err
	}
	if err := reg.AddDescription(desc); err != nil {
		return nil, fmt.Errorf("deploy: own description: %w", err)
	}
	db, err := store.Open(filepath.Join(dir, DatabaseFile))
	if err != nil {
		return nil, err
	}
	in := &Instance{Config: cfg, Dir: dir, Store: db, HTTP: client, Logf: log.Printf}
	if err := in.restoreMembers(reg); err != nil {
		db.Close()
		return nil, err
	}
	in.Fetcher = &registry.Fetcher{Registry: reg, HTTP: client, Origin: in.origin}
	in.CW, err = commonwealth.New(commonwealth.Config{
		Identity:    protocol.Identity{Instance: cfg.Instance, Layer: record.Commonwealth, KeyID: cfg.KeyID, Key: priv},
		Description: desc, Registry: reg, Store: db, HTTP: client,
		Witnesses:  ledger.WitnessPolicy{Witnesses: cfg.Witnesses, Threshold: cfg.WitnessThreshold},
		Multiplier: cfg.Multiplier,
		Discover:   in.Fetcher.Discover,
		Logf:       func(f string, a ...any) { in.Logf(f, a...) },
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return in, nil
}

// restoreMembers adds each member's attestation and the description it was
// attested from to the registry, so members are trusted from the start.
func (in *Instance) restoreMembers(reg *registry.Registry) error {
	members, err := in.Store.Members()
	if err != nil {
		return err
	}
	for _, m := range members {
		rec, err := in.Store.Record(m.Attestation)
		if err != nil {
			return err
		}
		if err := reg.AddAttestation(rec.Envelope); err != nil {
			return fmt.Errorf("deploy: restoring %s: %w", m.Instance, err)
		}
		if err := reg.AddDescription(m.Description); err != nil && !errors.Is(err, registry.ErrStale) {
			return fmt.Errorf("deploy: restoring %s: %w", m.Instance, err)
		}
	}
	return nil
}

func (in *Instance) origin(instance string) string {
	if o, ok := in.Config.Peers[instance]; ok {
		return o
	}
	return "https://" + instance
}

// Refresh fetches the current description of every member and witness, so
// key rotations and new endpoints are picked up. Members that cannot be
// reached keep their last known description.
func (in *Instance) Refresh(ctx context.Context) error {
	members, err := in.Store.Members()
	if err != nil {
		return err
	}
	seen := map[string]bool{in.Config.Instance: true}
	var errs []error
	for _, id := range in.Config.Witnesses {
		seen[id] = true
		if err := in.Fetcher.Discover(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	}
	for _, m := range members {
		if seen[m.Instance] {
			continue
		}
		if err := in.Fetcher.Discover(ctx, m.Instance); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.Instance, err))
		}
	}
	in.mu.Lock()
	in.refreshed = len(errs) == 0
	in.mu.Unlock()
	return errors.Join(errs...)
}

// Refreshed reports whether the last Refresh reached everyone.
func (in *Instance) Refreshed() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.refreshed
}

// Run refreshes members and witnesses now and every 6 hours, retrying
// every 5 minutes after a failure, until ctx is done.
func (in *Instance) Run(ctx context.Context) {
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := in.Refresh(cctx)
		cancel()
		if err != nil {
			in.Logf("could not refresh every member, retrying in 5 minutes: %v", err)
			wait = 5 * time.Minute
			continue
		}
		wait = 6 * time.Hour
	}
}

// Handler returns the platform's web interface and protocol endpoints.
func (in *Instance) Handler() (http.Handler, error) {
	return web.New(in.CW, in.Store, true)
}

// Serve runs the platform until ctx is done.
func (in *Instance) Serve(ctx context.Context) error {
	h, err := in.Handler()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", in.Config.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 2 * time.Minute}
	go in.Run(ctx)
	errc := make(chan error, 1)
	go func() {
		if in.Config.TLSCert != "" {
			errc <- srv.ServeTLS(ln, in.Config.TLSCert, in.Config.TLSKey)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// Close waits for background work and closes the database.
func (in *Instance) Close() error {
	in.CW.Close()
	return in.Store.Close()
}

func httpClient(caFile string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("deploy: %s holds no PEM certificates", caFile)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		Proxy:           http.ProxyFromEnvironment,
	}}, nil
}

func readRecord(path string) (*record.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return record.Parse(data)
}

func saveJSON(path string, v any, fresh bool) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if fresh {
		return writeNew(path, data, 0o644)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
