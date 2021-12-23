package reporting

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/adevinta/vulcan-agent/log"
	report "github.com/adevinta/vulcan-report"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/config"
)

const (
	SummaryWidth = 30
	Width        = 100
	baseIndent   = 2
)

type cliVulnerability struct {
	Asset         string
	TrueAsset     string
	Severity      string
	Color         int
	Vulnerability report.Vulnerability
}

func summaryTable(s []*report.Report, l log.Logger) {
	data := make(map[string]int)
	for _, s := range s {
		for _, v := range s.Vulnerabilities {
			severity, _ := mapSeverity(v.Score)
			data[severity]++
		}
	}
	var summary string
	for _, d := range severities {
		color := 0
		if data[d.Name] != 0 {
			color = d.Color
		}
		summary = fmt.Sprintf("%s%s%s%s%s\n", summary, indentate(baseIndent), formatString(d.Name, color), strings.Repeat("·", SummaryWidth-len(d.Name)), strconv.Itoa(data[d.Name]))
	}
	if len(s) != 0 {
		l.Infof("\nSummary of the last scan:\n" + summary + "\n")
	} else {
		l.Infof("No vulnerabilities found during the last scan")
	}
}

func parseReports(reports []*report.Report, config *config.Config) []cliVulnerability {
	var c []cliVulnerability
	var cv cliVulnerability
	for _, r := range reports {
		for _, v := range r.Vulnerabilities {
			cv.Asset = r.Target
			cv.Severity, cv.Color = mapSeverity(v.Score)
			cv.Vulnerability = v
			for _, s := range config.Checks {
				if s.Id == r.CheckID {
					cv.TrueAsset = s.Target
				}
			}
			c = append(c, cv)
		}
	}
	return c
}

func printVulnerability(v cliVulnerability, l log.Logger) string {
	color := v.Color
	severity := v.Severity
	if v.Severity == "NONE" {
		color = 0
		severity = "INFORMATIONAL"
	}
	s := formatString(strings.Repeat("=", Width), color)
	n := (Width - len(severity)) / 2
	s = s + formatString(fmt.Sprintf("\n%s%s%s", strings.Repeat("=", n), severity, strings.Repeat("=", Width-n-len(severity))), color)
	asset := v.Asset
	if asset != v.TrueAsset {
		asset = fmt.Sprintf("%s (%s)", v.TrueAsset, v.Asset)
	}
	s = fmt.Sprintf("%s\n%s %s", s, formatString("ASSET:", 0), asset)
	s = fmt.Sprintf("\n%s\n\n%s %s", s, formatString("SUMMARY:", 0), v.Vulnerability.Summary)
	dlines := splitLines(v.Vulnerability.Description, baseIndent, Width)
	s = fmt.Sprintf("\n%s\n\n%s\n%s%s", s, formatString("DESCRIPTION:", 0), indentate(baseIndent), strings.Join(dlines, "\n"+indentate(baseIndent)))
	if len(v.Vulnerability.Details) != 0 {
		dlines = splitLines(v.Vulnerability.Details, baseIndent, Width)
		s = fmt.Sprintf("%s\n\n%s\n%s%s", s, formatString("DETAILS:", 0), indentate(baseIndent), strings.Join(dlines, "\n"+indentate(baseIndent)))
	}
	if len(v.Vulnerability.References) != 0 && v.Vulnerability.References[0] != "" {
		sep := "\n" + indentate(baseIndent) + "- "
		s = fmt.Sprintf("%s\n\n%s%s%s", s, formatString("REFERENCES:", 0), sep, strings.Join(v.Vulnerability.References, sep))
	}
	if len(v.Vulnerability.Resources) != 0 {
		for _, r := range v.Vulnerability.Resources {
			if len(r.Rows) != 0 {
				s = fmt.Sprintf("\n%s\n\n%s", s, formatString(r.Name+":", 0))
				for _, rs := range r.Rows {
					for k, v := range rs {
						if len(v) != 0 {
							ts := splitLines(v, baseIndent, Width-baseIndent-len(k)-2)
							s = fmt.Sprintf("%s\n%s%s: %s", s, indentate(baseIndent), formatString(k, 0), strings.Join(ts, "\n"+indentate(baseIndent+len(k)+2)))
						}
					}
					s = fmt.Sprintf("%s\n", s)
				}
			}
		}
	}
	s = fmt.Sprintf("%s\n\n", s)
	return s
}

func mapSeverity(score float32) (string, int) {
	for _, s := range severities {
		if score >= s.Threshold {
			return s.Name, s.Color
		}
	}
	return "NONE", 0
}

func splitLines(s string, indent int, width int) []string {
	var lines []string
	for pointer := 0; pointer < len(s); {
		if s[pointer:pointer+1] == " " || s[pointer:pointer+1] == "\n" {
			pointer++
		}
		npointer := pointer + width - indent
		if npointer > len(s) {
			npointer = len(s)
		} else if npointer-pointer+indent <= width {
			npointer = pointer + findLastSpace(s[pointer:npointer])
		}
		line := strings.ReplaceAll(string(s[pointer:npointer]), "\n", indentate(indent)+"\n")
		lines = append(lines, line)
		pointer = npointer
	}
	return lines
}

func findLastSpace(line string) int {
	nl := strings.Index(line, "\n")
	p := strings.LastIndex(line, " ")
	if nl != -1 {
		return nl
	}
	if p == -1 {
		return len(line)
	}
	return p
}

func formatString(s string, i int) string {
	if i == 0 {
		return fmt.Sprintf("\x1b[1m%s\x1b[0m", s)
	}
	c := strconv.Itoa(i)
	return fmt.Sprintf("\x1b[%s;1m%s\x1b[0m", c, s)
}

func indentate(indent int) string {
	i := strings.Repeat(" ", indent)
	return i
}
