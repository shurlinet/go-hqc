//go:build ignore

// Command check-upstream queries the official HQC GitLab repository for tags
// and reports whether any tags exist beyond the pinned v5.0.0 version.
//
// Exit 0: no new tags (up to date).
// Exit 1: new tags found (action needed).
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
	pinnedTag = "v5.0.0"
	// GitLab project ID for pqc-hqc/hqc (public, no auth needed).
	tagsURL = "https://gitlab.com/api/v4/projects/pqc-hqc%2Fhqc/repository/tags?per_page=20"
)

type gitlabTag struct {
	Name string `json:"name"`
}

func main() {
	resp, err := http.Get(tagsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: fetch tags: %v\n", err)
		os.Exit(2)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "ERROR: GitLab API returned %d\n", resp.StatusCode)
		os.Exit(2)
	}

	var tags []gitlabTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: parse tags: %v\n", err)
		os.Exit(2)
	}

	// Find tags that are version tags (start with "v") and come after pinnedTag.
	var newer []string
	foundPinned := false
	for _, t := range tags {
		if t.Name == pinnedTag {
			foundPinned = true
			continue
		}
		if strings.HasPrefix(t.Name, "v") && t.Name > pinnedTag {
			newer = append(newer, t.Name)
		}
	}

	if !foundPinned {
		fmt.Fprintf(os.Stderr, "WARNING: pinned tag %s not found in upstream tags\n", pinnedTag)
	}

	if len(newer) == 0 {
		fmt.Printf("check-upstream: OK (pinned=%s, no newer tags)\n", pinnedTag)
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "check-upstream: NEWER TAGS FOUND (pinned=%s)\n", pinnedTag)
	for _, t := range newer {
		fmt.Fprintf(os.Stderr, "  %s\n", t)
	}
	fmt.Fprintf(os.Stderr, "Action: review upstream changes and update go-hqc.\n")
	os.Exit(1)
}
