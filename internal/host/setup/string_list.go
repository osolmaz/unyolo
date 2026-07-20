package setup

import "fmt"

// StringListFlag collects exact repeated string flag values.
type StringListFlag []string

func (values *StringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func (values *StringListFlag) String() string { return fmt.Sprint([]string(*values)) }
