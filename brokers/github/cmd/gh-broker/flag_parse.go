package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
)

func parseCommandFlags(stderr io.Writer, fs *flag.FlagSet, output *bytes.Buffer, args []string, invalidMessage string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, output)
			return exitError{code: 0}
		}
		return exitError{code: 64, message: invalidMessage}
	}
	return nil
}

func parseRequiredFlagCommand(stderr io.Writer, args []string, name, invalidMessage, missingMessage string, bind func(*flag.FlagSet), required ...*string) error {
	var output bytes.Buffer
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(&output)
	bind(fs)
	if err := parseCommandFlags(stderr, fs, &output, args, invalidMessage); err != nil {
		return err
	}
	if fs.NArg() != 0 || missingRequiredValue(required) {
		return exitError{code: 64, message: missingMessage}
	}
	return nil
}

func missingRequiredValue(values []*string) bool {
	for _, value := range values {
		if *value == "" {
			return true
		}
	}
	return false
}
