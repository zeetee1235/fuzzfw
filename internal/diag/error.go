// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package diag

import (
	"fmt"

	"github.com/fuzzfw/fuzzfw/internal/exitcode"
)

// Error is an expected failure with a diagnostic code and process exit code.
type Error struct {
	Code        string
	Message     string
	ExitCode    int
	Target      string
	Evidence    []string
	Remediation string
	Err         error
}

func (e *Error) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// Diagnostic converts the error into the artifact representation.
func (e *Error) Diagnostic() Diagnostic {
	d := New(e.Code, e.Message).WithTarget(e.Target).WithEvidence(e.Evidence...)
	d.Remediation = e.Remediation
	return d
}

// NewError creates an expected error with a diagnostic code.
func NewError(code, message string) *Error {
	return &Error{Code: code, Message: message, ExitCode: exitcode.Incomplete}
}

// NewUsageError creates a user/configuration error (exit code 3).
func NewUsageError(code, message string) *Error {
	return &Error{Code: code, Message: message, ExitCode: exitcode.Usage}
}

// Wrap adds a diagnostic code to an existing error.
func Wrap(code, message string, err error) *Error {
	return &Error{Code: code, Message: message, ExitCode: exitcode.Incomplete, Err: err}
}
