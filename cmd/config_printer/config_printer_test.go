/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package config_printer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/config"
)

// Mock configuration setup
func setupMockConfig(t *testing.T) error {
	// Set default config
	config.SetBaseDefaultsInConfig(viper.GetViper())
	viper.Set("ConfigDir", t.TempDir())
	if err := config.SetServerDefaults(viper.GetViper()); err != nil {
		return err
	}
	if err := config.SetClientDefaults(viper.GetViper()); err != nil {
		return err
	}
	// Setting Non-default values
	viper.Set("Logging.Cache.Http", "info")
	viper.Set("Logging.Cache.Xrootd", "info")
	viper.Set("Logging.Level", "info")
	viper.Set("Logging.Origin.Http", "info")

	return nil
}

// TestConfigGet verifies the correct working of the `config get` command.
// It checks for the correct output with different numbers of search parameters
// and ensures that the search space is adjusted based on the given flags.
func TestConfigGet(t *testing.T) {

	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	if err := setupMockConfig(t); err != nil {
		t.Fatalf("Error: %v", err)
	}

	testCases := []struct {
		name        string
		args        []string // Arguments passed to the command, including flags
		expected    []string // Expected lines to appear in stdout
		notExpected []string // Lines that should NOT appear in stdout
	}{
		{
			name:        "no-arguments",
			args:        []string{},
			expected:    []string{`logging.cache.http: "info"`, `logging.cache.xrootd: "info"`, `logging.level: "info"`, `logging.origin.http: "info"`},
			notExpected: []string{},
		},
		{
			name:        "match-http",
			args:        []string{"Http", "level"},
			expected:    []string{`logging.cache.http: "info"`, `logging.level: "info"`, `logging.origin.http: "info"`},
			notExpected: []string{`logging.cache.xrootd: "info"`},
		},

		{
			name:        "match-http-with-origin-flag",
			args:        []string{"Http", "-m", "origin"},
			expected:    []string{`logging.origin.http: "info"`},
			notExpected: []string{`logging.cache.http: "info"`, `logging.cache.xrootd: "info"`, `logging.level: "info"`},
		},
	}

	batchTest := func(t *testing.T, arguments []string, expectedLines []string, notExpectedLines []string) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			// Read from the pipe concurrently
			n, err := io.Copy(&buf, r)
			if err != nil {
				log.Errorf("failed to copy to output buffer: %v. Copied %d bytes before failure", err, n)
			}
			done <- struct{}{}
		}()

		ConfigCmd.SetArgs(append([]string{"get"}, arguments...))
		err := ConfigCmd.Execute()
		assert.NoError(t, err)

		// Close the write end of the pipe and wait for the reader to finish
		w.Close()
		<-done
		os.Stdout = oldStdout

		got := strings.TrimSpace(strings.ToLower(buf.String()))

		for _, expected := range expectedLines {
			expectedLower := strings.ToLower(expected)
			assert.Contains(t, got, expectedLower, fmt.Sprintf("Expected line %q not found in output", expected))
		}

		for _, notExpected := range notExpectedLines {
			notExpectedLower := strings.ToLower(notExpected)
			assert.NotContains(t, got, notExpectedLower, fmt.Sprintf("Line %q should not be in output", notExpected))
		}

		if t.Failed() {
			log.Debugln("Test Failed! Captured Output:\n", buf.String()) // Print full terminal output
		}
	}

	// Run through all the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			batchTest(t, tc.args, tc.expected, tc.notExpected)
		})
	}
}

// TestConfigSummary verifies the correct working of the `config summary` command.
// It checks that default values are not included in the output, while non-default
// values set in the config are.
func TestConfigSummary(t *testing.T) {

	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	if err := setupMockConfig(t); err != nil {
		t.Fatalf("Error: %v", err)
	}

	// Set a value same as default value
	viper.Set("Debug", false)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		// Read from the pipe concurrently
		n, err := io.Copy(&buf, r)
		if err != nil {
			log.Errorf("failed to copy to output buffer: %v. Copied %d bytes before failure", err, n)
		}
		done <- struct{}{}
	}()

	ConfigCmd.SetArgs([]string{"summary"})
	err := ConfigCmd.Execute()
	assert.NoError(t, err)

	// Close the write end of the pipe and wait for the reader to finish
	w.Close()
	<-done
	os.Stdout = oldStdout

	got := strings.TrimSpace(strings.ToLower(buf.String()))

	expectedLines := []string{`logging:`, `    cache:`, `    origin:`, `    level: info`, `        http: info`}
	notExpectedLines := []string{`debug: true`}

	for _, expected := range expectedLines {
		expectedLower := strings.ToLower(expected)
		assert.Contains(t, got, expectedLower, fmt.Sprintf("Expected line %q not found in output", expected))
	}

	for _, notExpected := range notExpectedLines {
		notExpectedLower := strings.ToLower(notExpected)
		assert.NotContains(t, got, notExpectedLower, fmt.Sprintf("Line %q should not be in output", notExpected))
	}

	if t.Failed() {
		log.Debugln("Test Failed! Captured Output:\n", buf.String()) // Print full terminal output
	}

}

// TestFormatValue verifies the correct working of the formatValue function.
func TestFormatValue(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{
			input:    map[string]struct{}{"deprecated": {}},
			expected: "[\"deprecated\"]",
		},
		{
			input:    nil,
			expected: "none",
		},
		{
			input:    []string{"origin", "director", "registry"},
			expected: "[\"origin\", \"director\", \"registry\"]",
		},
		{
			input:    "/etc/pelican/issuer.jwk",
			expected: "\"/etc/pelican/issuer.jwk\"",
		},
		{
			input:    42,
			expected: "42",
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := formatValue(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
