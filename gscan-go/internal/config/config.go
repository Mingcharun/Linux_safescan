package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const Version = "v0.1.0-go"
const Author = "Mingcha_run"
const RepositoryURL = "https://github.com/Mingcharun/Linux_safescan"

// Options captures CLI settings for the scanner.
type Options struct {
	Version         bool
	Full            bool
	Debug           bool
	Diff            bool
	Suggestion      bool
	Programme       bool
	SkipForeignIP   bool
	TimeRange       string
	InstallJob      bool
	JobHour         int
	LogBackup       bool
	OutputRoot      string
	RulesDir        string
	GeoIPDB         string
	RootkitSource   string
	WebshellRules   string
	SystemHashDB    string
	FindingHashDB   string
	SearchOnly      bool
	DisableLogScan  bool
	DisableWebshell bool
	DisableRootkit  bool
}

// Parse converts command-line args into Options.
func Parse(args []string) (Options, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Options{}, fmt.Errorf("get working directory: %w", err)
	}

	moduleRoot := filepath.Clean(cwd)
	defaultRules := filepath.Join(moduleRoot, "..", "GScan", "lib", "malware")
	defaultGeoIP := filepath.Join(moduleRoot, "..", "GScan", "lib", "core", "ip", "17monipdb.dat")
	defaultRootkit := filepath.Join(moduleRoot, "..", "GScan", "lib", "plugins", "Rootkit_Analysis.py")
	defaultWebshell := filepath.Join(moduleRoot, "..", "GScan", "lib", "plugins", "webshell_rule")
	defaultOutput := filepath.Join(moduleRoot, "runtime")
	defaultSystemHashDB := filepath.Join(defaultOutput, "db", "system_hashes.txt")
	defaultFindingHashDB := filepath.Join(defaultOutput, "db", "findings_hashes.txt")

	fs := flag.NewFlagSet("gscan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var opts Options
	fs.BoolVar(&opts.Version, "version", false, "show current version")
	fs.BoolVar(&opts.SkipForeignIP, "overseas", false, "skip foreign IP matching")
	fs.BoolVar(&opts.Full, "full", false, "enable full malware rule scanning")
	fs.BoolVar(&opts.Debug, "debug", false, "enable debug output")
	fs.BoolVar(&opts.Diff, "dif", false, "compare with the last run and only output diffs")
	fs.BoolVar(&opts.Suggestion, "sug", false, "include investigation guidance")
	fs.BoolVar(&opts.Programme, "pro", false, "include initial remediation suggestions")
	fs.StringVar(&opts.TimeRange, "time", "", "search files changed in a time range, e.g. '2026-03-20 00:00:00~2026-03-20 23:59:59'")
	fs.BoolVar(&opts.InstallJob, "job", false, "print a crontab line for scheduled execution")
	fs.BoolVar(&opts.LogBackup, "log", false, "pack common security logs")
	fs.StringVar(&opts.OutputRoot, "output", defaultOutput, "output directory")
	fs.StringVar(&opts.RulesDir, "rules-dir", defaultRules, "malware indicator directory")
	fs.StringVar(&opts.GeoIPDB, "geoip-db", defaultGeoIP, "17mon IP database path")
	fs.StringVar(&opts.RootkitSource, "rootkit-source", defaultRootkit, "Rootkit_Analysis.py path")
	fs.StringVar(&opts.WebshellRules, "webshell-rules", defaultWebshell, "webshell yara rule directory")
	fs.StringVar(&opts.SystemHashDB, "hash-db", defaultSystemHashDB, "hash baseline file for system binaries")
	fs.StringVar(&opts.FindingHashDB, "finding-hash-db", defaultFindingHashDB, "hash file for diff mode findings")
	fs.BoolVar(&opts.DisableLogScan, "disable-log-scan", false, "disable login log analysis")
	fs.BoolVar(&opts.DisableWebshell, "disable-webshell", false, "disable webshell scanning")
	fs.BoolVar(&opts.DisableRootkit, "disable-rootkit", false, "disable rootkit scanning")

	var rawHour string
	fs.StringVar(&rawHour, "hour", "0", "run scheduled scan every N hours")

	if err := fs.Parse(args); err != nil {
		return Options{}, err
	}

	if strings.TrimSpace(rawHour) != "" {
		hour, err := strconv.Atoi(rawHour)
		if err != nil || hour < 0 {
			return Options{}, errors.New("--hour must be a non-negative integer")
		}
		opts.JobHour = hour
	}

	opts.SearchOnly = strings.TrimSpace(opts.TimeRange) != ""
	return opts, nil
}
