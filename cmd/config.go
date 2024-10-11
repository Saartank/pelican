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

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/param"
)

var (
	configCmd = &cobra.Command{
		Use:   "config",
		Short: "View the configuration parameters set for the Pelican",
	}

	configTestCmd = &cobra.Command{
		Use:   "test",
		Short: "View the configuration parameters set for the Pelican",
		Run:   configTest,
	}

	configDumpCmd = &cobra.Command{
		Use:   "dump",
		Short: "View all the configuration parameters set for the Pelican",
		Run:   configDump,
	}

	configGetCmd = &cobra.Command{
		Use:   "get",
		Short: "Prints out all configuration variables and the values matching arguments",
		Run:   configGet,
	}

	format string
)

func configTest( /*cmd*/ *cobra.Command /*args*/, []string) {
	fmt.Println("You have run config Test!")
	rawConfig, _ := param.UnmarshalConfig()
	bytes, _ := json.MarshalIndent(*rawConfig, "", "  ")
	fmt.Println(string(bytes))
}

func configDump(cmd *cobra.Command, args []string) {
	settings := viper.AllSettings()

	switch format {
	case "yaml":
		yamlData, err := yaml.Marshal(settings)
		if err != nil {
			fmt.Printf("Error marshaling config to YAML: %v", err)
		}
		fmt.Println(string(yamlData))
	case "json":
		jsonData, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config to JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	default:
		fmt.Printf("Unsupported format: %s. Use 'yaml' or 'json'.", format)
	}
}

type Match struct {
	OriginalKey      string
	HighlightedKey   string
	HighlightedValue string
}

func configGet(cmd *cobra.Command, args []string) {
	keys := viper.AllKeys()

	var matches []Match

	for _, key := range keys {
		value := viper.Get(key)
		valueStr := fmt.Sprintf("%v", value)

		highlightedKey := key
		highlightedValue := valueStr
		matchesFound := false

		if len(args) == 0 {
			matchesFound = true
		} else {
			for _, arg := range args {
				argLower := strings.ToLower(arg)

				if strings.Contains(strings.ToLower(key), argLower) {
					highlightedKey = highlightSubstring(key, arg, color.FgYellow)
					matchesFound = true
				}

				if strings.Contains(strings.ToLower(valueStr), argLower) {
					highlightedValue = highlightSubstring(valueStr, arg, color.FgYellow)
					matchesFound = true
				}
			}
		}

		if matchesFound {
			matches = append(matches, Match{
				OriginalKey:      key,
				HighlightedKey:   highlightedKey,
				HighlightedValue: highlightedValue,
			})
		}
	}

	if len(matches) == 0 && len(args) > 0 {
		fmt.Println("No matching configuration parameters found.")
		return
	}

	// Sort the matches by the original keys (case-insensitive)
	sort.Slice(matches, func(i, j int) bool {
		return strings.ToLower(matches[i].OriginalKey) < strings.ToLower(matches[j].OriginalKey)
	})

	for _, match := range matches {
		fmt.Printf("%s: %s\n", match.HighlightedKey, match.HighlightedValue)
	}
}

// highlightSubstring highlights all occurrences of the substring in the string
func highlightSubstring(s, substr string, colorAttr color.Attribute) string {
	sLower := strings.ToLower(s)
	substrLower := strings.ToLower(substr)
	substrLen := len(substr)

	var result strings.Builder
	start := 0

	for {
		idx := strings.Index(sLower[start:], substrLower)
		if idx == -1 {
			result.WriteString(s[start:])
			break
		}

		idx += start
		result.WriteString(s[start:idx])
		matchedText := s[idx : idx+substrLen]
		highlighted := color.New(colorAttr).Sprint(matchedText)
		result.WriteString(highlighted)
		start = idx + substrLen
	}

	return result.String()
}

func init() {
	configCmd.AddCommand(configTestCmd)
	configCmd.AddCommand(configDumpCmd)
	configCmd.AddCommand(configGetCmd)
	configDumpCmd.Flags().StringVarP(&format, "format", "o", "yaml", "Output format (yaml or json)")
}
