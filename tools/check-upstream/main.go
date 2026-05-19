//go:build ignore

// Command check-upstream queries the official HQC GitLab repository for tags
// and the next-release branch HEAD, reporting whether anything has changed
// beyond the pinned commit.
//
// Exit 0: no changes (up to date).
// Exit 1: new tags or branch has advanced (action needed).
// Exit 2: network/API error.
//
// Usage:
//
//	go run tools/check-upstream/main.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	pinnedTag    = "v5.0.0"
	pinnedCommit = "161cd4fdf6b4a5198cf40b3a1243f9f27f13e03d"
	pinnedBranch = "next-release"

	tagsURL   = "https://gitlab.com/api/v4/projects/pqc-hqc%2Fhqc/repository/tags?per_page=20"
	branchURL = "https://gitlab.com/api/v4/projects/pqc-hqc%2Fhqc/repository/branches/" + pinnedBranch
)

type gitlabTag struct {
	Name string `json:"name"`
}

type gitlabBranch struct {
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
}

func main() {
	changed := false

	// Check for new tags.
	resp, err := http.Get(tagsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: fetch tags: %v\n", err)
		os.Exit(2)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "ERROR: GitLab tags API returned %d\n", resp.StatusCode)
		os.Exit(2)
	}

	var tags []gitlabTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: parse tags: %v\n", err)
		os.Exit(2)
	}

	var newer []string
	for _, t := range tags {
		if strings.HasPrefix(t.Name, "v") && t.Name > pinnedTag {
			newer = append(newer, t.Name)
		}
	}

	if len(newer) > 0 {
		fmt.Fprintf(os.Stderr, "NEW TAGS beyond %s:\n", pinnedTag)
		for _, t := range newer {
			fmt.Fprintf(os.Stderr, "  %s\n", t)
		}
		changed = true
	}

	// Check if next-release branch has advanced beyond pinned commit.
	resp2, err := http.Get(branchURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: fetch branch: %v\n", err)
		os.Exit(2)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 200 {
		var branch gitlabBranch
		if err := json.NewDecoder(resp2.Body).Decode(&branch); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: parse branch: %v\n", err)
			os.Exit(2)
		}
		if branch.Commit.ID != pinnedCommit {
			fmt.Fprintf(os.Stderr, "BRANCH %s ADVANCED:\n  pinned: %s\n  current: %s\n",
				pinnedBranch, pinnedCommit[:12], branch.Commit.ID[:12])
			changed = true
		}
	}

	if changed {
		fmt.Fprintf(os.Stderr, "Action: review upstream changes and update go-hqc.\n")
		os.Exit(1)
	}

	fmt.Printf("check-upstream: OK (pinned=%s, commit=%s, no changes)\n", pinnedTag, pinnedCommit[:12])
}
