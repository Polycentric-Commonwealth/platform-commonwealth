// Command pccommonwealth runs the Commonwealth platform.
//
//	pccommonwealth init -dir DIR [flags]             create a deployment
//	pccommonwealth anchor -dir DIR                   print the trust anchor members pin
//	pccommonwealth official add|reset|disable|list   manage officials' accounts
//	pccommonwealth uniqueness deal -dir DIR [flags]  create a uniqueness key and publish its configuration
//	pccommonwealth serve -dir DIR                    run a deployment
//
// Run any command with -h for its flags.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/polycentric-commonwealth/foundation/uniqueness"

	"github.com/polycentric-commonwealth/platform-commonwealth/internal/deploy"
	"github.com/polycentric-commonwealth/platform-commonwealth/internal/store"
)

const usage = `usage:
  pccommonwealth init -dir DIR -instance ID -name NAME -base-url URL [flags]
  pccommonwealth anchor -dir DIR
  pccommonwealth official add -dir DIR -user USER -name NAME -role admin|members|treasurer|auditor
  pccommonwealth official reset|disable -dir DIR -user USER
  pccommonwealth official list -dir DIR
  pccommonwealth uniqueness deal -dir DIR -epoch N -threshold T -operator ID [-operator ID ...] -out DIR
  pccommonwealth serve -dir DIR
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "init":
		err = initCmd(rest)
	case "anchor":
		err = anchorCmd(rest)
	case "official":
		err = officialCmd(rest)
	case "uniqueness":
		err = uniquenessCmd(rest)
	case "serve":
		err = serve(rest)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pccommonwealth:", err)
		os.Exit(1)
	}
}

// listFlag collects a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func pairs(list []string, what string) (map[string]string, error) {
	m := map[string]string{}
	for _, item := range list {
		k, v, ok := strings.Cut(item, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("%s must be written ID=VALUE, got %q", what, item)
		}
		m[k] = v
	}
	return m, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "directory for the new deployment")
	instance := fs.String("instance", "", "the Commonwealth's instance identifier, a domain name")
	name := fs.String("name", "Commonwealth", "its name")
	baseURL := fs.String("base-url", "", "public https URL of the platform, ending in /")
	listen := fs.String("listen", ":8443", "address to serve on")
	tlsCert := fs.String("tls-cert", "", "certificate file, to serve HTTPS directly (otherwise run behind a TLS proxy)")
	tlsKey := fs.String("tls-key", "", "private key file for -tls-cert")
	caFile := fs.String("ca-file", "", "extra PEM certificates to trust when reaching other instances")
	threshold := fs.Int("witness-threshold", 0, "how many witnesses must cosign a checkpoint (default: all of them)")
	multiplier := fs.String("multiplier", "", "audit repayment multiplier (default 3)")
	admin := fs.String("admin", "admin", "username of the first admin official")
	adminName := fs.String("admin-name", "Administrator", "name of the first admin official")
	var witnesses, peers listFlag
	fs.Var(&witnesses, "witness", "witness instance, usually a member (repeatable)")
	fs.Var(&peers, "peer", "reach an instance at another origin, ID=https://host:port (repeatable)")
	fs.Parse(args)
	if *dir == "" {
		return errors.New("init: -dir is required")
	}
	peerMap, err := pairs(peers, "-peer")
	if err != nil {
		return err
	}
	if *threshold == 0 {
		*threshold = len(witnesses)
	}
	cfg := deploy.Config{
		Instance: *instance, Name: *name, BaseURL: *baseURL, Listen: *listen, TLSCert: *tlsCert, TLSKey: *tlsKey,
		Witnesses: witnesses, WitnessThreshold: *threshold, Multiplier: *multiplier, Peers: peerMap, CAFile: *caFile,
	}
	if len(cfg.Peers) == 0 {
		cfg.Peers = nil
	}
	anchor, err := deploy.Init(*dir, cfg)
	if err != nil {
		return err
	}
	db, err := deploy.OpenStore(*dir)
	if err != nil {
		return err
	}
	defer db.Close()
	password, err := store.GeneratePassword()
	if err != nil {
		return err
	}
	if err := db.AddOfficial(*admin, *adminName, store.RoleAdmin, password); err != nil {
		return err
	}
	fmt.Printf(`Created the deployment for %s in %s.

First admin official: %s
Password (shown once): %s

Trust anchor for members to pin (pcstate init -anchor):
  %s

Next:
  pccommonwealth serve -dir %s
Then attest each Region or State on the Members page, from its signed description.
`, *instance, *dir, *admin, password, anchor, *dir)
	return nil
}

func anchorCmd(args []string) error {
	fs := flag.NewFlagSet("anchor", flag.ExitOnError)
	dir := fs.String("dir", "", "deployment directory")
	fs.Parse(args)
	anchor, err := deploy.Anchor(*dir)
	if err != nil {
		return err
	}
	fmt.Println(anchor)
	return nil
}

func officialCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pcstate official add|reset|disable|list -dir DIR ...")
	}
	sub := args[0]
	fs := flag.NewFlagSet("official "+sub, flag.ExitOnError)
	dir := fs.String("dir", "", "deployment directory")
	user := fs.String("user", "", "username")
	name := fs.String("name", "", "full name (add)")
	role := fs.String("role", store.RoleAuditor, "admin, members, treasurer or auditor (add)")
	fs.Parse(args[1:])
	if *dir == "" {
		return errors.New("official: -dir is required")
	}
	db, err := deploy.OpenStore(*dir)
	if err != nil {
		return err
	}
	defer db.Close()
	switch sub {
	case "list":
		list, err := db.Officials()
		if err != nil {
			return err
		}
		for _, o := range list {
			status := "active"
			if o.Disabled {
				status = "disabled"
			}
			fmt.Printf("%-20s %-10s %-9s %s\n", o.Username, o.Role, status, o.Name)
		}
		return nil
	case "add", "reset":
		if *user == "" {
			return errors.New("official: -user is required")
		}
		password, err := store.GeneratePassword()
		if err != nil {
			return err
		}
		if sub == "add" {
			err = db.AddOfficial(*user, *name, *role, password)
		} else if err = db.SetPassword(*user, password); err == nil {
			err = db.SetDisabled(*user, false)
		}
		if err != nil {
			return err
		}
		if err := db.LogAction("(command line)", map[string]string{"add": "added official", "reset": "reset password"}[sub], *user); err != nil {
			return err
		}
		fmt.Printf("Password for %s (shown once): %s\n", *user, password)
		return nil
	case "disable":
		if *user == "" {
			return errors.New("official: -user is required")
		}
		if err := db.SetDisabled(*user, true); err != nil {
			return err
		}
		fmt.Printf("Disabled %s and signed them out everywhere.\n", *user)
		return db.LogAction("(command line)", "disabled official", *user)
	}
	return fmt.Errorf("official: unknown command %q", sub)
}

func uniquenessCmd(args []string) error {
	if len(args) == 0 || args[0] != "deal" {
		return errors.New("usage: pccommonwealth uniqueness deal -dir DIR -epoch N -threshold T -operator ID ... -out DIR")
	}
	fs := flag.NewFlagSet("uniqueness deal", flag.ExitOnError)
	dir := fs.String("dir", "", "deployment directory (stop the server first)")
	epoch := fs.Int64("epoch", 1, "key epoch: one more than the current one")
	threshold := fs.Int("threshold", 0, "how many operators must take part in each evaluation")
	out := fs.String("out", "", "new directory for the operators' secret shares")
	var operators listFlag
	fs.Var(&operators, "operator", "operator instance, in share order (repeatable)")
	fs.Parse(args[1:])
	if *dir == "" || *out == "" || len(operators) == 0 || *threshold < 1 {
		return errors.New("uniqueness deal: -dir, -out, -threshold and at least one -operator are required")
	}
	commitments, shares, err := uniqueness.Deal(*threshold, len(operators))
	if err != nil {
		return err
	}
	in, err := deploy.Open(*dir)
	if err != nil {
		return err
	}
	defer in.Close()
	cfg := &uniqueness.Config{Suite: uniqueness.SuiteID, Epoch: *epoch, Commitments: commitments, Registry: in.Config.Instance}
	for i, op := range operators {
		cfg.Operators = append(cfg.Operators, uniqueness.Operator{Instance: op, Index: shares[i].Index})
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.Mkdir(*out, 0o700); err != nil {
		return fmt.Errorf("uniqueness deal: -out must be a new directory: %w", err)
	}
	for i, op := range operators {
		if err := os.WriteFile(filepath.Join(*out, op+".share"), []byte(shares[i].String()+"\n"), 0o600); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := in.CW.SetUniquenessConfig(ctx, cfg); err != nil {
		if _, _, cerr := in.CW.UniquenessConfig(); cerr != nil || !strings.Contains(err.Error(), "cosign") {
			return err
		}
		fmt.Fprintln(os.Stderr, "warning: the configuration is published, but the checkpoint was not fully cosigned:", err)
	}
	fmt.Printf(`Published uniqueness configuration epoch %d: %d of %d operators.

The operators' secret shares are in %s, one file per operator.
Deliver each file to its operator over a secure channel, then delete the directory.
Anyone holding %d shares can compute every token.
`, *epoch, *threshold, len(operators), *out, *threshold)
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("dir", "", "deployment directory")
	fs.Parse(args)
	if *dir == "" {
		return errors.New("serve: -dir is required")
	}
	in, err := deploy.Open(*dir)
	if err != nil {
		return err
	}
	defer in.Close()
	log.SetPrefix("pccommonwealth: ")
	in.Logf = log.Printf
	log.Printf("%s (%s) serving on %s, public at %s", in.Config.Name, in.Config.Instance, in.Config.Listen, in.Config.BaseURL)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = in.Serve(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	log.Println("stopped")
	return err
}

func readFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}
