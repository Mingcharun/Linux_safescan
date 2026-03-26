package rules

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Corpus stores text indicators loaded from the original malware rules.
type Corpus struct {
	Indicators []string
}

// Load reads indicator files from a directory.
func Load(dir string) (*Corpus, error) {
	c := &Corpus{Indicators: []string{}}
	if dir == "" {
		return c, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("stat rules dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules path is not a directory: %s", dir)
	}

	seen := make(map[string]struct{})
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if len(line) <= 5 || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ".") || !strings.Contains(line, ".") {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			c.Indicators = append(c.Indicators, line)
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("walk rules dir: %w", err)
	}

	return c, nil
}

// Match returns the first indicator found inside content.
func (c *Corpus) Match(content string) string {
	if c == nil {
		return ""
	}
	for _, indicator := range c.Indicators {
		if strings.Contains(content, indicator) {
			return indicator
		}
	}
	return ""
}
