/*
Copyright 2021 Adevinta
*/

package reporting

import (
	"encoding/json"
	"fmt"
	"os"

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

func Generate(cfg *config.Config, results *results.ResultsServer, l log.Logger) (int, error) {

	if cfg.Reporting.Format != "json" {
		return 1, fmt.Errorf("report format unknown %s", cfg.Reporting.Format)
	}

	// Create an slice of reports and get max score.
	var slice []*report.Report
	var maxScore float32 = -1.0
	for _, report := range results.Checks {
		slice = append(slice, report)
		for _, v := range report.Vulnerabilities {
			if v.Score > float32(maxScore) {
				maxScore = v.Score
			}
		}
	}

	// Print summary table
	summaryTable(slice, l)

	outputFile := cfg.Reporting.OutputFile
	if outputFile != "" {

		// json: Just print the reports
		str, _ := json.Marshal(slice)

		if outputFile == "-" {
			fmt.Fprint(os.Stderr, string(str))
		} else {
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY, 0644)
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
		vs := parseReports(slice, cfg)
		var rs string
		for _, s := range severities {
			for _, v := range vs {
				if v.Severity == s.Name {
					rs = fmt.Sprintf("%s%s", rs, printVulnerability(v, l))
				}
			}
		}
		if len(rs) > 0 {
			l.Infof("\nVulnerabilities details:%s", rs)
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

	// Default requested severity as MEDIUM
	requested := severities[1]
	for _, t := range severities {
		if cfg.Reporting.Threshold == t.Name {
			requested = t
			break
		}
	}
	if current.Threshold >= requested.Threshold {
		return current.Exit, nil
	}

	return 0, nil
}
