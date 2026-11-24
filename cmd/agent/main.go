package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"link-observatory/internal/protocol"
)

const credentialsFile = "credentials.json"

var (
	version   = "dev"
	nodeIDRE  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	errDown   = errors.New("probe is not running")
	errLocked = errors.New("probe directory is in use")
)

type credentials struct {
	Manager    string `json:"manager"`
	NodeID     string `json:"node_id"`
	Credential string `json:"credential"`
	Enrolled   bool   `json:"enrolled"`
}

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agent {register|run|status|stop|version}")
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	directory := flags.String("dir", "", "private probe instance directory")
	var manager, nodeID *string
	switch command {
	case "register":
		manager = flags.String("manager", "", "HTTPS manager URL")
		nodeID = flags.String("node", "", "manager-issued node ID")
	case "run", "status", "stop":
	default:
		return fmt.Errorf("unknown agent command %q", command)
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("provide --dir and no positional arguments")
	}
	if err := enterDirectory(*directory, command == "register"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if command == "stop" {
				return nil
			}
			if command == "status" {
				return errDown
			}
		}
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch command {
	case "register":
		return register(ctx, *manager, *nodeID, os.Stdin)
	case "run":
		return run(ctx)
	case "status":
		if err := control(ctx, "status"); err != nil {
			return err
		}
		fmt.Println("probe is running")
		return nil
	default:
		return stop(ctx)
	}
}

func enterDirectory(dir string, create bool) error {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("probe directory must be private and owned by the current user")
	}
	// Unix resolves the relative socket name here, including for long home paths.
	return os.Chdir(dir)
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func register(ctx context.Context, managerURL, nodeID string, input io.Reader) error {
	managerURL, err := validateManagerURL(managerURL)
	if err != nil {
		return err
	}
	if !nodeIDRE.MatchString(nodeID) {
		return errors.New("invalid node ID")
	}
	lock, err := lockDirectory()
	if err != nil {
		return err
	}
	defer lock.Close()

	state, err := loadCredentials()
	if errors.Is(err, os.ErrNotExist) {
		state = credentials{Manager: managerURL, NodeID: nodeID}
	} else if err != nil {
		return err
	}
	if state.Manager != managerURL || state.NodeID != nodeID {
		return errors.New("probe directory already belongs to another node or manager")
	}
	if state.Enrolled {
		fmt.Println("probe already registered")
		return nil
	}
	client := newManagerClient(state)
	defer client.http.CloseIdleConnections()
	if state.Credential != "" &&
		client.request(ctx, "GET", "/api/agent/config", nil, nil, true) == nil {
		// The manager accepted the previous request even though we missed its response.
		state.Enrolled = true
		return writePrivateJSON(credentialsFile, state)
	}

	token, err := bufio.NewReader(io.LimitReader(input, 4097)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read enrollment token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 4096 {
		return errors.New("read a valid enrollment token from standard input")
	}
	if state.Credential == "" {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		state.Credential = base64.RawURLEncoding.EncodeToString(key[:])
		// Save before the request so retries reuse the same credential.
		if err := writePrivateJSON(credentialsFile, state); err != nil {
			return err
		}
	}
	client.state = state
	request := protocol.Enrollment{NodeID: nodeID, Token: token, Credential: state.Credential, Version: version}
	if err := client.request(ctx, "POST", "/api/agent/register", request, nil, false); err != nil {
		return fmt.Errorf("register probe: %w", err)
	}
	state.Enrolled = true
	return writePrivateJSON(credentialsFile, state)
}

func loadCredentials() (credentials, error) {
	var state credentials
	if err := readPrivateJSON(credentialsFile, &state); err != nil {
		return state, err
	}
	manager, err := validateManagerURL(state.Manager)
	key, keyErr := base64.RawURLEncoding.DecodeString(state.Credential)
	if err != nil || manager != state.Manager || !nodeIDRE.MatchString(state.NodeID) || keyErr != nil || len(key) != 32 {
		return credentials{}, errors.New("invalid local probe credentials")
	}
	return state, nil
}

func readPrivateJSON(name string, dest any) error {
	fd, err := syscall.Open(name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return fmt.Errorf("%s must be a private file owned by the current user", name)
	}
	const maxLocalJSON = 4 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxLocalJSON+1))
	if err != nil {
		return err
	}
	if len(data) > maxLocalJSON {
		return fmt.Errorf("%s is too large", name)
	}
	return json.Unmarshal(data, dest)
}

func writePrivateJSON(name string, value any) error {
	file, err := os.CreateTemp(".", ".probe-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(value); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), name); err != nil {
		return err
	}
	directory, err := os.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
