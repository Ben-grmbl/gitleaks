package config

import (
	"fmt"
	"regexp"
	"strings"
)

type AllowlistMatchCondition int

const (
	AllowlistMatchOr AllowlistMatchCondition = iota
	AllowlistMatchAnd
)

func (a AllowlistMatchCondition) String() string {
	return [...]string{
		"OR",
		"AND",
	}[a]
}

// Allowlist allows a rule to be ignored for specific
// regexes, paths, and/or commits
type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// MatchCondition determines whether all criteria must match.
	MatchCondition AllowlistMatchCondition

	// Commits is a slice of commit SHAs that are allowed to be ignored. Defaults to "OR".
	Commits []string

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// Can be `match` or `line`.
	//
	// If `match` the _Regexes_ will be tested against the match of the _Rule.Regex_.
	//
	// If `line` the _Regexes_ will be tested against the entire line.
	//
	// If RegexTarget is empty, it will be tested against the found secret.
	RegexTarget string

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string
}

// CommitAllowed returns true if the commit is allowed to be ignored.
func (a *Allowlist) CommitAllowed(c string) bool {
	if c == "" {
		return false
	}
	for _, commit := range a.Commits {
		if commit == c {
			return true
		}
	}
	return false
}

// PathAllowed returns true if the path is allowed to be ignored.
func (a *Allowlist) PathAllowed(path string) bool {
	return anyRegexMatch(path, a.Paths)
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(secret string) bool {
	return anyRegexMatch(secret, a.Regexes)
}

func (a *Allowlist) ContainsStopWord(s string) bool {
	s = strings.ToLower(s)
	for _, stopWord := range a.StopWords {
		if strings.Contains(s, strings.ToLower(stopWord)) {
			return true
		}
	}
	return false
}

func (a *Allowlist) Validate() error {
	// Disallow empty allowlists.
	if len(a.Commits) == 0 &&
		len(a.Paths) == 0 &&
		len(a.Regexes) == 0 &&
		len(a.StopWords) == 0 {
		return fmt.Errorf("[[rules.allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords")
	}

	return nil
}
