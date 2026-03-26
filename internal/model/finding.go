package model

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"time"
)

// Severity describes the risk level of a finding.
type Severity string

const (
	SeverityInfo       Severity = "info"
	SeveritySuspicious Severity = "suspicious"
	SeverityRisk       Severity = "risk"
)

// HostInfo captures basic host metadata for the scan report.
type HostInfo struct {
	Hostname string    `json:"hostname"`
	IP       string    `json:"ip"`
	OS       string    `json:"os"`
	Time     time.Time `json:"time"`
}

// Finding models a suspicious or malicious observation.
type Finding struct {
	Category  string    `json:"category"`
	Name      string    `json:"name"`
	File      string    `json:"file,omitempty"`
	PID       string    `json:"pid,omitempty"`
	Time      string    `json:"time,omitempty"`
	User      string    `json:"user,omitempty"`
	Info      string    `json:"info"`
	Consult   string    `json:"consult,omitempty"`
	Severity  Severity  `json:"severity"`
	Programme string    `json:"programme,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Fingerprint returns the stable identity hash used for diff mode.
func (f Finding) Fingerprint() string {
	sum := md5.Sum([]byte(strings.Join([]string{
		f.Category,
		f.Name,
		f.File,
		f.PID,
		f.Time,
		f.Info,
	}, "|")))
	return hex.EncodeToString(sum[:])
}

// ScanReport is the top-level persisted output of a run.
type ScanReport struct {
	Version      string    `json:"version"`
	Author       string    `json:"author"`
	Repository   string    `json:"repository"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	Host         HostInfo  `json:"host"`
	Findings     []Finding `json:"findings"`
	NewFindings  []Finding `json:"new_findings,omitempty"`
	OpenServices []string  `json:"open_services,omitempty"`
	Timeline     []string  `json:"timeline,omitempty"`
	Warnings     []string  `json:"warnings,omitempty"`
	DiffMode     bool      `json:"diff_mode"`
	Suggestion   bool      `json:"suggestion"`
	Programme    bool      `json:"programme"`
}
