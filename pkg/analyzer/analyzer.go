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
	"compress/bzip2"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
    "fmt"
	"log"

	"github.com/devmatic-it/debcvescan/pkg/dpkg"
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
	// UNKNOWN unknown impact
	UNKNOWN

	// IGNORE end of life and outdated issues
	IGNORE
)

func (serverity Severity) String() string {
	return [...]string{"OPEN", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "IGNORE"}[serverity]
}

type jsonData map[string]map[string]jsonVulnerability

// debian-security json
type jsonVulnerability struct {
	Description string                 `json:"description"`
	Releases    map[string]jsonRelease `json:"releases"`
}

type jsonRelease struct {
	FixedVersion string `json:"fixed_version"`
	Status       string `json:"status"`
	Urgency      string `json:"urgency"`
}

type jsonUbuntuData map[string]map[string]jsonUbuntuVulnerability

type jsonUbuntuVulnerability struct {
	Releases map[string]map[string]jsonUbuntuRelease `json:"releases"`
}

type jsonUbuntuRelease struct {
	Status []string `json:"status"`
}

// converts urgency to serverity
func severityFromUrgency(urgency string) Severity {
	switch urgency {

	case "low", "low*", "low**", "LOW":
		return LOW

	case "medium", "medium*", "medium**", "MEDIUM":
		return MEDIUM

	case "high", "high*", "high**", "HIGH":
		return HIGH

	case "not yet assigned":
		return OPEN

	case "end-of-life", "unimportant":
		return IGNORE

	default:
		return UNKNOWN
	}
}

// ScanPackages scans the given list of debian packages for vulnerabilties
func ScanPackages(installedPackages dpkg.PackageList) VulnerabilityReport {

	// var severityForID []*cveSeverites
	severityForID := make( map[string]string )

	jsonfile, err := os.Open("./debcveseverity.json")
	if err != nil {
		log.Fatal(err)
	}

	err = json.NewDecoder(jsonfile).Decode(&severityForID)
	if err != nil {
		panic(err)
	}

	cvejson, err := os.Open("./debcvelist.json")

	var report VulnerabilityReport
	if err != nil {

		client := &http.Client{}
		req, err := http.NewRequest("GET", "https://security-tracker.debian.org/tracker/data/json", nil)
		if err != nil {
			panic(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}

		report = scanPackagesFromReader(resp.Body, installedPackages, severityForID)
	} else {
		report = scanPackagesFromReader(cvejson, installedPackages, severityForID)
	}

	debianId, _, codename := GetOSInfo()
	if debianId == "ubuntu" {
		report = ubuntuBackports(&report, codename)
	}
	return report
}

// ubuntuBackports helper function to update CVEs with fixed version numbers in Ubuntu distro.
// Ubuntu often backport security patches to older versions
func ubuntuBackports(vulnerabilites *VulnerabilityReport, codename string) VulnerabilityReport {

	report := NewVulnerabilityReport()
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://people.canonical.com/~ubuntu-security/cvescan/ubuntu-vuln-db-"+codename+".json.bz2", nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	bz2Reader := bzip2.NewReader(resp.Body)
	var data jsonUbuntuData
	err = json.NewDecoder(bz2Reader).Decode(&data)
	if err != nil {
		println() // something with the bzip2 reader seems not working well
	}

	for _, vul := range vulnerabilites.Vulnerabilities {
		for cve, details := range data["data"] {
			if vul.CVE == cve {
				pkgDetails, exists := details.Releases[codename][vul.PackageName]
				if exists {
					// update patched version
					if pkgDetails.Status[0] == "released" {
						vul.FixedVersion = pkgDetails.Status[1]
					}
				}
			}
		}

		if dpkg.IsAffectedVersion(vul.InstalledVersion, vul.FixedVersion) {
			report.AddVulnerability(vul)
		}
	}

	return report
}

// scans for vulnerabilities in given packages
func scanPackagesFromReader(source io.Reader, installedPackages dpkg.PackageList, severityForID map[string]string) VulnerabilityReport {
	report := NewVulnerabilityReport()

	var data jsonData
	err := json.NewDecoder(source).Decode(&data)
	if err != nil {
		panic(err)
	}

	whitelist := NewWhitelist()
	report.CountTotal = 0
	cveNames := make(map[string]string)
	for pkgName, pkgNode := range data {
		// if !whitelist.HasPackage(pkgName) {
			if strings.HasPrefix(pkgName, "strongswan") {
     		fmt.Printf("Got %-16s \n", pkgName)
			pkgInstalledVersion, pkgExists := installedPackages[pkgName]
			if pkgExists {
				fmt.Printf("Exists %-16s \n", pkgInstalledVersion)

				for vulnName, vulnNode := range pkgNode {
					for _, releaseNode := range vulnNode.Releases {
						if !strings.HasPrefix(vulnName, "CVE-") || releaseNode.Status == "undetermined" {
							continue
						}

						_, exists := cveNames[vulnName]
						// Here we can rework to show no fixed, but bullseye have
						if !exists && dpkg.IsAffectedVersion(pkgInstalledVersion, releaseNode.FixedVersion) {
							cveNames[vulnName] = pkgName
							severity := severityFromUrgency(releaseNode.Urgency)

							if releaseNode.Status == "Open" {
								severity = OPEN
							}

							// fmt.Println("Key:", vulnName, "Value:", severityForID[vulnName])
							if severityForID[vulnName] != "" {
								severity = severityFromUrgency(severityForID[vulnName])
							}


							if !whitelist.HasCVE(vulnName) {
								report.AddVulnerability(Vulnerability{severity, vulnName, vulnNode.Description, pkgName, pkgInstalledVersion, releaseNode.FixedVersion})
							}
						} else {
							if severityForID[vulnName] == "HIGH" {
								fmt.Printf("%-16s %-32s %-6s %s \n", pkgName, pkgInstalledVersion, severityForID[vulnName], vulnName)
								// fmt.Println("Key:", vulnName, "Value:", severityForID[vulnName])
							}
						}

					}
				}
			}
		}
	}

	return report
}
