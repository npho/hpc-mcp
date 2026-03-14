package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

type apiKeyRecord struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	APIKey    string `json:"api_key"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stderr)
		return 1
	}

	command := args[0]
	if command == "-h" || command == "--help" || command == "help" {
		printRootUsage(stdout)
		return 0
	}

	switch command {
	case "create":
		config, err := parseCreateArgs(args[1:])
		if err != nil {
			if errors.Is(err, errHelpRequested) {
				printCreateUsage(stdout)
				return 0
			}
			fmt.Fprintf(stderr, "Error: %v\n", err)
			printCreateUsage(stderr)
			return 1
		}
		return runCreate(config, stdout, stderr)
	case "get":
		config, err := parseGetArgs(args[1:])
		if err != nil {
			if errors.Is(err, errHelpRequested) {
				printGetUsage(stdout)
				return 0
			}
			fmt.Fprintf(stderr, "Error: %v\n", err)
			printGetUsage(stderr)
			return 1
		}
		return runGet(config, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Error: unknown command %q\n", command)
		printRootUsage(stderr)
		return 1
	}

}

type createConfig struct {
	Username string
	Force    bool
	DBFile   string
}

type getConfig struct {
	Username string
	HasUser  bool
	ShowKey  bool
	DBFile   string
}

var errHelpRequested = errors.New("help requested")

func parseCreateArgs(args []string) (createConfig, error) {
	config := createConfig{DBFile: defaultDBPath()}

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-h", "--help":
			return createConfig{}, errHelpRequested
		case "-f", "--force":
			config.Force = true
		case "--db-file":
			index++
			if index >= len(args) {
				return createConfig{}, errors.New("missing value for --db-file")
			}
			config.DBFile = args[index]
		default:
			if strings.HasPrefix(arg, "--db-file=") {
				config.DBFile = strings.TrimPrefix(arg, "--db-file=")
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return createConfig{}, fmt.Errorf("unknown flag %s", arg)
			}
			if config.Username != "" {
				return createConfig{}, errors.New("create expects exactly one username")
			}
			config.Username = arg
		}
	}

	if config.Username == "" {
		return createConfig{}, errors.New("missing username")
	}

	return config, nil
}

func parseGetArgs(args []string) (getConfig, error) {
	config := getConfig{DBFile: defaultDBPath()}

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-h", "--help":
			return getConfig{}, errHelpRequested
		case "--show-key":
			config.ShowKey = true
		case "--db-file":
			index++
			if index >= len(args) {
				return getConfig{}, errors.New("missing value for --db-file")
			}
			config.DBFile = args[index]
		default:
			if strings.HasPrefix(arg, "--db-file=") {
				config.DBFile = strings.TrimPrefix(arg, "--db-file=")
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return getConfig{}, fmt.Errorf("unknown flag %s", arg)
			}
			if config.HasUser {
				return getConfig{}, errors.New("get accepts at most one username")
			}
			config.Username = arg
			config.HasUser = true
		}
	}

	return config, nil
}

func printRootUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-admin.go <command> [options]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Admin utilities for MCP API key create/get operations.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  create      Issue or rotate an API key for a username.")
	fmt.Fprintln(out, "  get         Get active key metadata (latest row) for one or all users.")
}

func printCreateUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-admin.go create [--db-file PATH] [--force|-f] <username>")
}

func printGetUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-admin.go get [--db-file PATH] [--show-key] [username]")
}

func defaultDBPath() string {
	if _, sourceFile, _, ok := runtime.Caller(0); ok {
		return filepath.Join(filepath.Dir(sourceFile), "api_keys.jsonl")
	}

	executablePath, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(executablePath), "api_keys.jsonl")
	}

	return "api_keys.jsonl"
}

func resolveDBPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		switch {
		case path == "~":
			path = homeDir
		case strings.HasPrefix(path, "~/"):
			path = filepath.Join(homeDir, path[2:])
		}
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	return filepath.Clean(absolutePath), nil
}

func validateUsername(username string) error {
	if usernamePattern.MatchString(username) {
		return nil
	}

	return errors.New(
		"Invalid username. Expected pattern: start with a lowercase letter, then lowercase letters/digits/_/- (max 32 chars).",
	)
}

func utcNowISO8601() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
}

func parseCreatedAt(createdAt string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, createdAt)
}

func generateAPIKey() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func parseRecord(rawLine string, dbPath string, lineNumber int, stderr io.Writer) (*apiKeyRecord, error) {
	var generic any
	if err := json.Unmarshal([]byte(rawLine), &generic); err != nil {
		fmt.Fprintf(stderr, "Warning: ignored malformed JSON at %s:%d.\n", dbPath, lineNumber)
		return nil, nil
	}

	objectValue, ok := generic.(map[string]any)
	if !ok {
		fmt.Fprintf(stderr, "Warning: ignored non-object JSON at %s:%d.\n", dbPath, lineNumber)
		return nil, nil
	}

	if len(objectValue) != 3 {
		fmt.Fprintf(stderr, "Warning: ignored row with unexpected schema at %s:%d.\n", dbPath, lineNumber)
		return nil, nil
	}

	usernameValue, hasUsername := objectValue["username"]
	createdAtValue, hasCreatedAt := objectValue["created_at"]
	apiKeyValue, hasAPIKey := objectValue["api_key"]
	if !hasUsername || !hasCreatedAt || !hasAPIKey {
		fmt.Fprintf(stderr, "Warning: ignored row with unexpected schema at %s:%d.\n", dbPath, lineNumber)
		return nil, nil
	}

	username, usernameOK := usernameValue.(string)
	createdAt, createdAtOK := createdAtValue.(string)
	apiKey, apiKeyOK := apiKeyValue.(string)
	if !usernameOK || !createdAtOK || !apiKeyOK {
		fmt.Fprintf(stderr, "Warning: ignored row with invalid field values at %s:%d.\n", dbPath, lineNumber)
		return nil, nil
	}

	if _, err := parseCreatedAt(createdAt); err != nil {
		fmt.Fprintf(stderr, "Warning: ignored row with invalid field values at %s:%d.\n", dbPath, lineNumber)
		return nil, nil
	}

	return &apiKeyRecord{Username: username, CreatedAt: createdAt, APIKey: apiKey}, nil
}

func usernameExists(dbPath string, username string, stderr io.Writer) (bool, error) {
	file, err := os.Open(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}

		record, err := parseRecord(raw, dbPath, lineNumber, stderr)
		if err != nil {
			return false, err
		}
		if record != nil && record.Username == username {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil
}

func appendRecord(dbPath string, record apiKeyRecord) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}

	file, err := os.OpenFile(dbPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}

	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}

	return nil
}

func loadActiveRecords(dbPath string, stderr io.Writer) (map[string]apiKeyRecord, error) {
	active := make(map[string]apiKeyRecord)

	file, err := os.Open(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return active, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}

		record, err := parseRecord(raw, dbPath, lineNumber, stderr)
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}

		current, exists := active[record.Username]
		if !exists {
			active[record.Username] = *record
			continue
		}

		recordTime, err := parseCreatedAt(record.CreatedAt)
		if err != nil {
			return nil, err
		}
		currentTime, err := parseCreatedAt(current.CreatedAt)
		if err != nil {
			return nil, err
		}

		if recordTime.After(currentTime) {
			active[record.Username] = *record
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return active, nil
}

func formatGetOutput(record apiKeyRecord, showKey bool) (string, error) {
	type outputRecord struct {
		Username  string `json:"username"`
		CreatedAt string `json:"created_at"`
		APIKey    string `json:"api_key"`
	}

	output := outputRecord{
		Username:  record.Username,
		CreatedAt: record.CreatedAt,
		APIKey:    "<redacted>",
	}
	if showKey {
		output.APIKey = record.APIKey
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		return "", err
	}

	return strings.TrimSpace(buffer.String()), nil
}

func runCreate(config createConfig, stdout io.Writer, stderr io.Writer) int {
	dbPath, err := resolveDBPath(config.DBFile)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to resolve datastore: %v\n", err)
		return 1
	}

	if err := validateUsername(config.Username); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	exists, err := usernameExists(dbPath, config.Username, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to read datastore: %v\n", err)
		return 1
	}
	if exists && !config.Force {
		fmt.Fprintln(stderr, "Error: Username already exists in datastore. Use --force (or -f) to rotate and append a new key.")
		return 1
	}

	apiKey, err := generateAPIKey()
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to generate API key: %v\n", err)
		return 1
	}

	record := apiKeyRecord{
		Username:  config.Username,
		CreatedAt: utcNowISO8601(),
		APIKey:    apiKey,
	}

	if err := appendRecord(dbPath, record); err != nil {
		fmt.Fprintf(stderr, "Error: failed to write datastore: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "username: %s\n", record.Username)
	fmt.Fprintf(stdout, "created_at: %s\n", record.CreatedAt)
	fmt.Fprintf(stdout, "api_key: %s\n", record.APIKey)
	if config.Force {
		fmt.Fprintln(stdout, "status: rotated")
	} else {
		fmt.Fprintln(stdout, "status: issued")
	}
	fmt.Fprintf(stdout, "db_file: %s\n", dbPath)

	return 0
}

func runGet(config getConfig, stdout io.Writer, stderr io.Writer) int {
	dbPath, err := resolveDBPath(config.DBFile)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to resolve datastore: %v\n", err)
		return 1
	}

	if config.HasUser {
		if err := validateUsername(config.Username); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
	}

	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "Error: datastore not found at %s\n", dbPath)
			return 1
		}
		fmt.Fprintf(stderr, "Error: failed to read datastore: %v\n", err)
		return 1
	}

	activeRecords, err := loadActiveRecords(dbPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to read datastore: %v\n", err)
		return 1
	}

	if config.HasUser {
		record, exists := activeRecords[config.Username]
		if !exists {
			fmt.Fprintf(stderr, "Error: no records found for username %s\n", config.Username)
			return 1
		}

		formatted, err := formatGetOutput(record, config.ShowKey)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to encode output: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, formatted)
		return 0
	}

	usernames := make([]string, 0, len(activeRecords))
	for username := range activeRecords {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)

	for _, username := range usernames {
		formatted, err := formatGetOutput(activeRecords[username], config.ShowKey)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to encode output: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, formatted)
	}

	return 0
}
