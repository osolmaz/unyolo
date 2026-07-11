package main

import "testing"

func TestCommandPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("command smoke marker")
	}
}
