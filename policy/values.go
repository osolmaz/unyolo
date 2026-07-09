package policy

// SingletonValues converts provider scalar values into canonical policy lists.
func SingletonValues(values map[string]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string][]string, len(values))
	for key, value := range values {
		out[key] = []string{value}
	}
	return out
}

// FirstValue returns the first canonical value or an empty string.
func FirstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
