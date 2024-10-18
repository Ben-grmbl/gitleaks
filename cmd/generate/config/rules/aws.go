package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AWS() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
		RuleID:      "aws-access-token",
		Regex: regexp.MustCompile(
			`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`),
		Keywords: []string{
			"AKIA",
			"ASIA",
			"ABIA",
			"ACCA",
		},
	}

	// validate
	tps := []string{utils.GenerateSampleSecret("AWS", "AKIALALEMEL33243OLIB")} // gitleaks:allow
	fps := []string{
		// wrong length to be a valid AWS key
		"ASIASIASIASIASIASIASIASIASIASI", // gitleaks:allow
		"AACCAACCAACCAACCAACCAACCAACCAA", // gitleaks:allow
	}

	return utils.Validate(r, tps, fps)
}
