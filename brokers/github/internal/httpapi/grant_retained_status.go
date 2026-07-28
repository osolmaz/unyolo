package httpapi

import "github.com/osolmaz/unyolo/authorization/grants"

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
	remaining, finite := grant.MaxUses.Remaining(grant.UsedCount, grant.ReservedCount)
	if !finite {
		return 0
	}
	return remaining
}
