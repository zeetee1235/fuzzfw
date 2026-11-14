// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package logx provides process-wide diagnostic logging. Artifact output never
// depends on this logger; it exists for humans and CI troubleshooting.
package logx

import (
	"io"
	"log"
	"os"
	"path/filepath"
)

type level int

const (
	levelError level = iota
	levelWarn
	levelInfo
	levelDebug
)

var (
	currentLevel = levelWarn
	logger       = log.New(os.Stderr, "", log.LstdFlags)
)

// Configure sets verbosity and optionally mirrors debug output to a file.
func Configure(verbose int, quiet bool, logFile string) error {
	var writers []io.Writer
	switch {
	case quiet:
		currentLevel = levelError
	case verbose >= 2:
		currentLevel = levelDebug
	case verbose == 1:
		currentLevel = levelInfo
	default:
		currentLevel = levelWarn
	}
	writers = append(writers, os.Stderr)
	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
			return err
		}
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		writers = append(writers, file)
		currentLevel = levelDebug
	}
	logger = log.New(io.MultiWriter(writers...), "", log.LstdFlags)
	return nil
}

// Debugf logs at debug level.
func Debugf(format string, args ...any) {
	if currentLevel >= levelDebug {
		logger.Printf("DEBUG "+format, args...)
	}
}

// Infof logs at info level.
func Infof(format string, args ...any) {
	if currentLevel >= levelInfo {
		logger.Printf("INFO "+format, args...)
	}
}

// Warnf logs at warning level.
func Warnf(format string, args ...any) {
	if currentLevel >= levelWarn {
		logger.Printf("WARN "+format, args...)
	}
}

// Errorf logs at error level.
func Errorf(format string, args ...any) {
	if currentLevel >= levelError {
		logger.Printf("ERROR "+format, args...)
	}
}
