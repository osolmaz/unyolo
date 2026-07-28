package httpapi

import "github.com/osolmaz/unyolo/authorization/grants"

const retainedGrantStatus = "retained"

func grantIsRetained(grant grants.Grant) bool {
	return grant.ReservationRetained
}

func apiGrantStatus(grant grants.Grant) string {
	if grantIsRetained(grant) {
		return retainedGrantStatus
	}
	return string(grant.Status)
}

func retainedGrantMatchesFilter(grant grants.Grant, filter string) (bool, bool) {
	if filter == retainedGrantStatus {
		return grantIsRetained(grant), true
	}
	if grantIsRetained(grant) {
		return filter == "", true
	}
	return false, false
}
