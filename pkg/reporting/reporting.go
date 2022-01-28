/*
Copyright 2021 Adevinta
*/

package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adevinta/vulcan-agent/log"
	report "github.com/adevinta/vulcan-report"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/config"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/results"
)

type Severity struct {
	Name      string
	Threshold float32
	Exit      int
	Color     int
}

const (
	ErrorExitCode   = 1
	SuccessExitCode = 0
)

var severities = []Severity{
	{
		Name:      "CRITICAL",
		Threshold: 9.0,
		Exit:      104,
		Color:     35, // Purple
	},
	{
		Name:      "HIGH",
		Threshold: 7.0,
		Exit:      103,
		Color:     31, // Red
	},
	{
		Name:      "MEDIUM",
		Threshold: 4.0,
		Exit:      102,
		Color:     33, // Yellow
	},
	{
		Name:      "LOW",
		Threshold: 0.1,
		Exit:      101,
		Color:     36, // Light blue
	},
	{
		Name:      "NONE",
		Threshold: 100,
		Exit:      SuccessExitCode,
		Color:     36, // Light blue
	},
}

func isExcluded(v *ExtendedVulnerability, ex *[]config.Exclusion) bool {
	for _, e := range *ex {
		if strings.Contains(v.Target, e.Target) &&
			strings.Contains(v.Summary, e.Summary) &&
			strings.Contains(v.Fingerprint, e.Fingerprint) &&
			(strings.Contains(v.AffectedResource, e.AffectedResource) || strings.Contains(v.AffectedResourceString, e.AffectedResource)) {
			return true
		}
	}
	return false
}

func updateReport(e *ExtendedVulnerability, c *config.Check) {
	if e.Target != c.Target {
		e.Target = c.Target
		e.Details = strings.ReplaceAll(e.Details, c.NewTarget, c.Target)
		e.Details = strings.ReplaceAll(e.Details, c.NewTarget, c.Target)
		for i := range e.Recommendations {
			e.Recommendations[i] = strings.ReplaceAll(e.Recommendations[i], c.NewTarget, c.Target)
		}
		for _, rg := range e.Resources {
			for _, r := range rg.Rows {
				for k, v := range r {
					r[k] = strings.ReplaceAll(v, c.NewTarget, c.Target)
				}
			}
		}
	}
}

func parseReports(reports map[string]*report.Report, cfg *config.Config, l log.Logger) []ExtendedVulnerability {
	vulns := []ExtendedVulnerability{}
	for _, r := range reports {
		for i := range r.Vulnerabilities {
			v := r.Vulnerabilities[i]
			extended := ExtendedVulnerability{
				CheckData:     &r.CheckData,
				Vulnerability: &v,
				Severity:      mapSeverity(v.Score),
			}
			for _, s := range cfg.Checks {
				if s.Id == r.CheckID {
					updateReport(&extended, &s)
					break
				}
			}
			extended.Excluded = isExcluded(&extended, &cfg.Reporting.Exclusions)
			vulns = append(vulns, extended)
		}
	}
	return vulns
}

func Generate(cfg *config.Config, results *results.ResultsServer, l log.Logger) (int, error) {
	if cfg.Reporting.Format != "json" {
		return 1, fmt.Errorf("report format unknown %s", cfg.Reporting.Format)
	}

	// Default requested severity as MEDIUM
	requested := severities[1]
	for _, t := range severities {
		if cfg.Reporting.Threshold == t.Name {
			requested = t
			break
		}
	}

	// Print results when no output file is set
	vs := parseReports(results.Checks, cfg, l)

	// Print summary table
	summaryTable(vs, l)

	outputFile := cfg.Reporting.OutputFile
	if outputFile != "" {

		// TODO: Decide if we want to apply the threshold and exclusion filtering to the JSON.
		// Recreates the original report map filtering the Excluded and Threshold
		// json: Just print the reports as an slice
		m := map[string]*report.Report{}
		slice := []*report.Report{}
		for _, e := range vs {
			r, ok := m[e.CheckID]
			if !ok {
				r = &report.Report{CheckData: *e.CheckData}
				m[e.CheckID] = r
				slice = append(slice, r)
			}
			if !e.Excluded && e.Severity.Threshold >= requested.Threshold {
				r.Vulnerabilities = append(r.Vulnerabilities, *(e.Vulnerability))
			}
		}
		str, _ := json.Marshal(slice)
		if outputFile == "-" {
			fmt.Fprint(os.Stderr, string(str))
		} else {
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return 1, fmt.Errorf("unable to open report file %s %+v", outputFile, err)
			}
			defer f.Close()
			if _, err := f.Write(str); err != nil {
				return 1, fmt.Errorf("unable to write report file %s %+v", outputFile, err)
			}
		}
	} else {
		// Print results when no output file is set
		var rs string
		for _, s := range severities {
			for _, v := range vs {
				if v.Severity.Name == s.Name && !v.Excluded && v.Severity.Threshold >= requested.Threshold {
					rs = fmt.Sprintf("%s%s", rs, printVulnerability(&v, l))
				}
			}
		}
		if len(rs) > 0 {
			l.Infof("\nVulnerabilities details:\n%s", rs)
		}
	}

	var maxScore float32 = -1.0
	for _, v := range vs {
		if v.Score > float32(maxScore) {
			maxScore = v.Score
		}
	}

	// Find the highest severity for that Score
	current := severities[len(severities)-1]
	for _, t := range severities {
		if t.Threshold < maxScore {
			current = t
			break
		}
	}

	if current.Threshold >= requested.Threshold {
		return current.Exit, nil
	}

	return 0, nil
}
