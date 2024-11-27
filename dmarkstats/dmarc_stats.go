package dmarcstats

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"
)

// Report represents the analyzed DMARC report data
type Report struct {
	Domain              string             `json:"domain"`
	ReportPeriod        ReportDate         `json:"report_period"`
	TotalMessages       int                `json:"total_messages"`
	AuthResults         AuthResults        `json:"authentication_results"`
	DispositionAnalysis map[string]float64 `json:"disposition_analysis"`
	PolicyPublished     Policy             `json:"policy_published"`
	FailingIPs          []FailureDetail    `json:"failing_ips"`
}

// FailureDetail contains information about failing IPs
type FailureDetail struct {
	IP            string `json:"ip"`
	Count         int    `json:"message_count"`
	SPFResult     string `json:"spf_result"`
	DKIMResult    string `json:"dkim_result"`
	Disposition   string `json:"disposition"`
	HeaderFrom    string `json:"header_from"`
	SPFDomain     string `json:"spf_domain,omitempty"`
	DKIMDomain    string `json:"dkim_domain,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
}

type ReportDate struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type AuthResults struct {
	SPFPassCount        int     `json:"spf_pass"`
	SPFPassRate         float64 `json:"spf_pass_rate"`
	DKIMPassCount       int     `json:"dkim_pass"`
	DKIMPassRate        float64 `json:"dkim_pass_rate"`
	DMARCPassCount      int     `json:"dmarc_pass"`
	DMARCComplianceRate float64 `json:"dmarc_compliance_rate"`
}

type Policy struct {
	Domain string `xml:"domain" json:"domain"`
	ADKIM  string `xml:"adkim" json:"adkim"`
	ASPF   string `xml:"aspf" json:"aspf"`
	P      string `xml:"p" json:"p"`
	SP     string `xml:"sp" json:"sp"`
	PCT    string `xml:"pct" json:"pct"`
}

// DMARCFeedback represents the XML structure of a DMARC report
type DMARCFeedback struct {
	XMLName         xml.Name `xml:"feedback"`
	PolicyPublished struct {
		Domain string `xml:"domain"`
		ADKIM  string `xml:"adkim"`
		ASPF   string `xml:"aspf"`
		P      string `xml:"p"`
		SP     string `xml:"sp"`
		PCT    string `xml:"pct"`
	} `xml:"policy_published"`
	DateRange struct {
		Begin int64 `xml:"begin"`
		End   int64 `xml:"end"`
	} `xml:"report_metadata>date_range"`
	Records []Record `xml:"record"`
}

type Record struct {
	SourceIP        string `xml:"row>source_ip"`
	Count           int    `xml:"row>count"`
	PolicyEvaluated struct {
		Disposition string `xml:"disposition"`
		DKIM        string `xml:"dkim"`
		SPF         string `xml:"spf"`
	} `xml:"row>policy_evaluated"`
	Identifiers struct {
		HeaderFrom string `xml:"header_from"`
	} `xml:"identifiers"`
	AuthResults struct {
		SPF  SPFResult  `xml:"spf"`
		DKIM DKIMResult `xml:"dkim"`
	} `xml:"auth_results"`
}

type SPFResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

type DKIMResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

// AnalyzeDMARCReport parses an XML DMARC report and returns analyzed statistics
func AnalyzeDMARCReport(reader io.Reader) (*Report, error) {
	var feedback DMARCFeedback
	decoder := xml.NewDecoder(reader)
	if err := decoder.Decode(&feedback); err != nil {
		return nil, fmt.Errorf("failed to decode DMARC report: %w", err)
	}

	if len(feedback.Records) == 0 {
		return nil, fmt.Errorf("no records found in DMARC report")
	}

	report := &Report{
		Domain: feedback.PolicyPublished.Domain,
		ReportPeriod: ReportDate{
			Start: time.Unix(feedback.DateRange.Begin, 0).UTC(),
			End:   time.Unix(feedback.DateRange.End, 0).UTC(),
		},
		DispositionAnalysis: make(map[string]float64),
		PolicyPublished: Policy{
			Domain: feedback.PolicyPublished.Domain,
			ADKIM:  feedback.PolicyPublished.ADKIM,
			ASPF:   feedback.PolicyPublished.ASPF,
			P:      feedback.PolicyPublished.P,
			SP:     feedback.PolicyPublished.SP,
			PCT:    feedback.PolicyPublished.PCT,
		},
		FailingIPs: []FailureDetail{},
	}

	var totalMessages, spfPass, dkimPass, dmarcPass int
	dispositionCounts := make(map[string]int)

	for _, record := range feedback.Records {
		if record.Count <= 0 {
			continue // Skip invalid records
		}

		count := record.Count
		totalMessages += count

		// Count dispositions
		dispositionCounts[record.PolicyEvaluated.Disposition] += count

		spfResult := record.PolicyEvaluated.SPF
		dkimResult := record.PolicyEvaluated.DKIM

		if spfResult == "pass" {
			spfPass += count
		}
		if dkimResult == "pass" {
			dkimPass += count
		}
		if spfResult == "pass" || dkimResult == "pass" {
			dmarcPass += count
		}

		// Record failures (or partial failures)
		if spfResult != "pass" || dkimResult != "pass" {
			failureReason := determineFailureReason(spfResult, dkimResult)
			if failureReason != "" {
				detail := FailureDetail{
					IP:            record.SourceIP,
					Count:         count,
					SPFResult:     spfResult,
					DKIMResult:    dkimResult,
					Disposition:   record.PolicyEvaluated.Disposition,
					HeaderFrom:    record.Identifiers.HeaderFrom,
					FailureReason: failureReason,
				}

				if record.AuthResults.SPF.Domain != "" {
					detail.SPFDomain = record.AuthResults.SPF.Domain
				}
				if record.AuthResults.DKIM.Domain != "" {
					detail.DKIMDomain = record.AuthResults.DKIM.Domain
				}

				report.FailingIPs = append(report.FailingIPs, detail)
			}
		}
	}

	if totalMessages == 0 {
		return nil, fmt.Errorf("no valid messages found in DMARC report")
	}

	report.TotalMessages = totalMessages
	report.AuthResults = AuthResults{
		SPFPassCount:        spfPass,
		SPFPassRate:         roundToTwoDecimals(float64(spfPass) / float64(totalMessages) * 100),
		DKIMPassCount:       dkimPass,
		DKIMPassRate:        roundToTwoDecimals(float64(dkimPass) / float64(totalMessages) * 100),
		DMARCPassCount:      dmarcPass,
		DMARCComplianceRate: roundToTwoDecimals(float64(dmarcPass) / float64(totalMessages) * 100),
	}

	for disposition, count := range dispositionCounts {
		report.DispositionAnalysis[disposition] = roundToTwoDecimals(float64(count) / float64(totalMessages) * 100)
	}

	return report, nil
}

func determineFailureReason(spfResult, dkimResult string) string {
	if spfResult == "pass" && dkimResult == "pass" {
		return ""
	}
	if spfResult != "pass" && dkimResult != "pass" {
		return "Both SPF and DKIM failed"
	} else if spfResult != "pass" {
		return "SPF failed"
	} else if dkimResult != "pass" {
		return "DKIM failed"
	}
	return "Unknown failure"
}

func roundToTwoDecimals(num float64) float64 {
	return float64(int(num*100)) / 100
}
