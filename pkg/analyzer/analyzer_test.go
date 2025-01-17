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
	"os"
	"testing"

	"github.com/devmatic-it/debcvescan/pkg/dpkg"
	"gopkg.in/h2non/gock.v1"
)

func TestScanPackages(t *testing.T) {
	packages := dpkg.LoadInstalledPackages("../../data/dpkg/status")
	if packages == nil {
		t.Fail()
	}

	file, err := os.Open("../../data/json.json")
	if err != nil {
		t.Fail()
	}

	ubuntuFile, err := os.Open("../../data/ubuntu-vuln-db-focal.json.bz2")
	if err != nil {
		t.Fail()
	}

	defer gock.Off()
	gock.New("https://security-tracker.debian.org").
		Get("/tracker/data/json").Reply(200).Body(file)

	gock.New("https://people.canonical.com").
		Get("/~ubuntu-security/cvescan/ubuntu-vuln-db-focal.json.bz2").Reply(200).Body(ubuntuFile)

	report := ScanPackages(packages)

	if report.Vulnerabilities == nil {
		t.Fail()
	}

	if len(report.Vulnerabilities) == 0 {
		t.Fail()
	}

	vul := report.Vulnerabilities[0]
	if vul.PackageName == "" {
		t.Errorf("Expected package name, but found %s", vul.PackageName)
	}

	if !gock.IsDone() {
		t.Fail()
	}
}

func TestScanPackagesFromReader(t *testing.T) {
	packages := dpkg.LoadInstalledPackages("../../data/dpkg/status")
	if packages == nil {
		t.Fail()
	}

	file, err := os.Open("../../data/json.json")
	if err != nil {
		t.Fail()
	}

	report := scanPackagesFromReader(file, packages)
	if report.Vulnerabilities == nil {
		t.Fail()
	}

	if len(report.Vulnerabilities) == 0 {
		t.Fail()
	}

	vul := report.Vulnerabilities[0]
	if vul.PackageName == "" {
		t.Errorf("Expected package name, but found %s", vul.PackageName)
	}
}
