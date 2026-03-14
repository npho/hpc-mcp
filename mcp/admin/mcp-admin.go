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
	case "purge":
		config, err := parsePurgeArgs(args[1:])
		if err != nil {
			if errors.Is(err, errHelpRequested) {
				printPurgeUsage(stdout)
				return 0
			}
			fmt.Fprintf(stderr, "Error: %v\n", err)
			printPurgeUsage(stderr)
			return 1
		}
		return runPurge(config, stdout, stderr)
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

type purgeConfig struct {
	Usernames []string
	DBFile    string
}

type dbEntry struct {
	RawLine string
	Record  *apiKeyRecord
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

func parsePurgeArgs(args []string) (purgeConfig, error) {
	config := purgeConfig{DBFile: defaultDBPath()}

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-h", "--help":
			return purgeConfig{}, errHelpRequested
		case "--db-file":
			index++
			if index >= len(args) {
				return purgeConfig{}, errors.New("missing value for --db-file")
			}
			config.DBFile = args[index]
		default:
			if strings.HasPrefix(arg, "--db-file=") {
				config.DBFile = strings.TrimPrefix(arg, "--db-file=")
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return purgeConfig{}, fmt.Errorf("unknown flag %s", arg)
			}
			config.Usernames = append(config.Usernames, arg)
		}
	}

	return config, nil
}

func printRootUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-admin.go <command> [options]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Admin utilities for MCP API key create/get/purge operations.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  create      Issue or rotate an API key for a username.")
	fmt.Fprintln(out, "  get         Get active key metadata (latest row) for one or all users.")
	fmt.Fprintln(out, "  purge       Purge stale rotated keys while keeping active keys.")
}

func printCreateUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-admin.go create [--db-file PATH] [--force|-f] <username>")
}

func printGetUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-admin.go get [--db-file PATH] [--show-key] [username]")
}

func printPurgeUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-admin.go purge [--db-file PATH] [username ...]")
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

func loadDBEntries(dbPath string, stderr io.Writer) ([]dbEntry, error) {
	entries := make([]dbEntry, 0)

	file, err := os.Open(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return entries, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			entries = append(entries, dbEntry{RawLine: rawLine})
			continue
		}

		record, err := parseRecord(trimmed, dbPath, lineNumber, stderr)
		if err != nil {
			return nil, err
		}
		entries = append(entries, dbEntry{RawLine: rawLine, Record: record})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func rewriteEntries(dbPath string, lines []string) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(dbPath), "api_keys.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	for _, line := range lines {
		if _, err := tmpFile.WriteString(line + "\n"); err != nil {
			tmpFile.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, dbPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return nil
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

func runPurge(config purgeConfig, stdout io.Writer, stderr io.Writer) int {
	dbPath, err := resolveDBPath(config.DBFile)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to resolve datastore: %v\n", err)
		return 1
	}

	for _, username := range config.Usernames {
		if err := validateUsername(username); err != nil {
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

	entries, err := loadDBEntries(dbPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to read datastore: %v\n", err)
		return 1
	}

	counts := make(map[string]int)
	for _, entry := range entries {
		if entry.Record == nil {
			continue
		}
		counts[entry.Record.Username]++
	}

	targets := make(map[string]bool)
	if len(config.Usernames) > 0 {
		for _, username := range config.Usernames {
			targets[username] = true
		}
	} else {
		for username := range counts {
			targets[username] = true
		}
	}

	rotatedUsers := make([]string, 0)
	totalRemovable := 0
	for username := range targets {
		if counts[username] > 1 {
			rotatedUsers = append(rotatedUsers, username)
			totalRemovable += counts[username] - 1
		}
	}
	sort.Strings(rotatedUsers)

	if len(rotatedUsers) == 0 {
		fmt.Fprintln(stdout, "No rotated keys found for purge scope.")
	} else {
		fmt.Fprintln(stdout, "Users with rotated keys eligible for purge:")
		for _, username := range rotatedUsers {
			fmt.Fprintf(stdout, "- %s: %d rotated keys can be removed\n", username, counts[username]-1)
		}
	}
	fmt.Fprintf(stdout, "Total rotated keys removable: %d\n", totalRemovable)

	if totalRemovable == 0 {
		fmt.Fprintln(stdout, "Nothing to purge. Exiting without changes.")
		return 0
	}

	fmt.Fprint(stdout, "Proceed with purge? [Y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	response, readErr := reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		fmt.Fprintf(stderr, "Error: failed to read confirmation: %v\n", readErr)
		return 1
	}

	if strings.ToLower(strings.TrimSpace(response)) != "y" {
		fmt.Fprintln(stdout, "Purge cancelled.")
		return 0
	}

	keepIndex := make(map[string]int)
	keepCreatedAt := make(map[string]time.Time)
	for index, entry := range entries {
		if entry.Record == nil {
			continue
		}
		username := entry.Record.Username
		if !targets[username] || counts[username] <= 1 {
			continue
		}

		createdAt, err := parseCreatedAt(entry.Record.CreatedAt)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to parse timestamp during purge: %v\n", err)
			return 1
		}

		current, exists := keepCreatedAt[username]
		if !exists || createdAt.After(current) {
			keepCreatedAt[username] = createdAt
			keepIndex[username] = index
		}
	}

	filteredLines := make([]string, 0, len(entries))
	removed := 0
	for index, entry := range entries {
		if entry.Record == nil {
			filteredLines = append(filteredLines, entry.RawLine)
			continue
		}

		username := entry.Record.Username
		if targets[username] && counts[username] > 1 && keepIndex[username] != index {
			removed++
			continue
		}

		filteredLines = append(filteredLines, entry.RawLine)
	}

	// Acquire an advisory lock to prevent concurrent writers during purge.
	lockPath := dbPath + ".lock"
	for {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			if os.IsExist(err) {
				// Another process holds the lock; wait and retry.
				time.Sleep(100 * time.Millisecond)
				continue
			}
			fmt.Fprintf(stderr, "Error: failed to acquire purge lock: %v\n", err)
			return 1
		}
		// Ensure the lock is released when purge completes.
		defer func() {
			lockFile.Close()
			_ = os.Remove(lockPath)
		}()
		break
	}

	if err := rewriteEntries(dbPath, filteredLines); err != nil {
		fmt.Fprintf(stderr, "Error: failed to write datastore: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Purged rotated keys: %d\n", removed)
	fmt.Fprintf(stdout, "db_file: %s\n", dbPath)
	return 0
}
