package httpapi

import "github.com/osolmaz/brokerkit/grants"

func apiGrantStatus(grant grants.Grant) string {
	if grant.ReservationRetained {
		return "retained"
	}
	return string(grant.Status)
}

func grantUsesRemaining(grant grants.Grant) int {
	if grant.Status != grants.StatusActive || grant.ReservationRetained {
		return 0
	}
	return max(0, grant.MaxUses-grant.UsedCount-grant.ReservedCount)
}
