// Package operatorv1wire maps Operator V1 domain values to generated wire values.
package operatorv1wire

import (
	"github.com/oapi-codegen/nullable"
	"github.com/osolmaz/unyolo/authorization/budget"
)

// UseLimitToWire converts a required domain use limit to its nullable wire form.
func UseLimitToWire(limit usebudget.Limit) nullable.Nullable[int] {
	if limit.IsUnlimited() {
		return nullable.NewNullNullable[int]()
	}
	return nullable.NewNullableWithValue(int(limit))
}

// UseLimitFromWire converts a required nullable wire use limit to the domain.
func UseLimitFromWire(limit nullable.Nullable[int]) usebudget.Limit {
	if limit.IsNull() || !limit.IsSpecified() {
		return usebudget.Unlimited
	}
	return usebudget.Limit(limit.MustGet())
}
