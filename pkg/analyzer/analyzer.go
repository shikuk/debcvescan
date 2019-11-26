// Package analyzer Debian CVE Tracker Analyzer
// Copyright 2019 debcvescan authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package analyzer

import (
	"encoding/json"
	"github.com/devmatic-it/debcvescan/pkg/dpkg"
	"io"
	"net/http"
	"strings"
)

// Severity describs the severity
type Severity int

const (
	// OPEN open issue still beein investigated
	OPEN Severity = iota

	// HIGH  critical issue to be fixef
	HIGH

	// MEDIUM  medium severity
	MEDIUM

	// LOW  low severity
	LOW
	// UNKOWN unkown impact
	UNKOWN

	// IGNORE end of life and outdated issues
	IGNORE
)

func (serverity Severity) String() string {
	return [...]string{"OPEN", "HIGH", "MEDIUM", "LOW", "UNKOWN", "IGNORE"}[serverity]
}

// Vulnerability contains a vulnerability
type Vulnerability struct {
	Severity         Severity `json:"severity"`
	CVE              string   `json:"cve"`
	Description      string   `json:"description"`
	PackageName      string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
}

type jsonData map[string]map[string]jsonVulnerability

type jsonVulnerability struct {
	Description string                 `json:"description"`
	Releases    map[string]jsonRelease `json:"releases"`
}

type jsonRelease struct {
	FixedVersion string `json:"fixed_version"`
	Status       string `json:"status"`
	Urgency      string `json:"urgency"`
}

// converts urgency to serverity
func severityFromUrgency(urgency string) Severity {
	switch urgency {

	case "low", "low*", "low**":
		return LOW

	case "medium", "medium*", "medium**":
		return MEDIUM

	case "high", "high*", "high**":
		return HIGH

	case "not yet assigned":
		return UNKOWN

	case "end-of-life", "unimportant":
		return IGNORE

	default:
		return UNKOWN
	}
}

// ScanPackages scans the given list of debian packages for vulnerabilties
func ScanPackages(installedPackages dpkg.PackageList) []Vulnerability {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://security-tracker.debian.org/tracker/data/json", nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	return scanPackagesFromReader(resp.Body, installedPackages)
}

// scans for vulnerabilities in given packages
func scanPackagesFromReader(source io.Reader, installedPackages dpkg.PackageList) []Vulnerability {

	var vulnerabilities []Vulnerability

	var data jsonData
	err := json.NewDecoder(source).Decode(&data)
	if err != nil {
		panic(err)
	}

	cveNames := make(map[string]string)
	for pkgName, pkgNode := range data {
		pkgInstalledVersion, pkgExists := installedPackages[pkgName]
		if pkgExists {
			for vulnName, vulnNode := range pkgNode {
				for _, releaseNode := range vulnNode.Releases {
					if !strings.HasPrefix(vulnName, "CVE-") || releaseNode.Status == "undetermined" {
						continue
					}

					_, exists := cveNames[vulnName]
					if !exists && dpkg.IsAffectedVersion(pkgInstalledVersion, releaseNode.FixedVersion) {
						cveNames[vulnName] = pkgName
						severity := severityFromUrgency(releaseNode.Urgency)
						if releaseNode.Status == "Open" {
							severity = OPEN
						}

						if severity == LOW || severity == MEDIUM || severity == HIGH || severity == OPEN {
							vulnerabilities = append(vulnerabilities, Vulnerability{severity, vulnName, vulnNode.Description, pkgName, pkgInstalledVersion, releaseNode.FixedVersion})
						}
					}

				}
			}
		}

	}

	return vulnerabilities
}