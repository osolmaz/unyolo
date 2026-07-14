package main

import (
	"slices"
	"strings"
)

func buildHighRiskReview(rest []restCoverage, graphql []graphqlCoverage) highRiskReview {
	rules := map[string]string{
		"destructive":  "delete, removal, revocation, transfer, archival, cancellation, and termination mutations",
		"secret":       "secret, private-key, token, credential, and deploy-key mutations",
		"permission":   "permission, role, membership, collaborator, access, suspension, blocking, and bypass mutations",
		"billing":      "billing, spending, budget, sponsorship, invoice, and plan mutations",
		"organization": "organization-scoped mutations",
		"enterprise":   "enterprise-scoped mutations",
	}
	operations := map[string][]string{}
	for _, row := range rest {
		for _, class := range row.RiskClasses {
			values := row.CatalogOperations
			if len(values) == 0 {
				values = []string{"rest:" + row.UpstreamID}
			}
			operations[class] = append(operations[class], values...)
		}
	}
	for _, row := range graphql {
		if row.CatalogOperation == "" {
			continue
		}
		for _, class := range classifyGraphQLRiskClasses(row.RootType, row.Field) {
			operations[class] = append(operations[class], row.CatalogOperation)
		}
	}
	classes := make([]riskReviewClass, 0, len(rules))
	for name, rule := range rules {
		values := operations[name]
		slices.Sort(values)
		values = slices.Compact(values)
		classes = append(classes, riskReviewClass{Name: name, Rule: rule, Operations: values})
	}
	slices.SortFunc(classes, func(a, b riskReviewClass) int { return strings.Compare(a.Name, b.Name) })
	return highRiskReview{Version: 1, Classes: classes}
}
