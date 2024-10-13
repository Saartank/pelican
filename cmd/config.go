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
	"reflect"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/docs"
	"github.com/pelicanplatform/pelican/param"

	_ "embed"
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

	configManCmd = &cobra.Command{
		Use:   "man",
		Short: "Prints documentation for the config parmaeter matching best with the argument",
		Run:   configMan,
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
	rawConfig, err := param.UnmarshalConfig()
	if err != nil {
		fmt.Println("Error unmarshalling config:", err)
		return
	}

	configValues := make(map[string]string)
	extractConfigValues(rawConfig, "", configValues)

	var matches []Match

	for key, valueStr := range configValues {
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

	sort.Slice(matches, func(i, j int) bool {
		return strings.ToLower(matches[i].OriginalKey) < strings.ToLower(matches[j].OriginalKey)
	})

	for _, match := range matches {
		fmt.Printf("%s: %s\n", match.HighlightedKey, match.HighlightedValue)
	}
}

// extractConfigValues recursively extracts key-value pairs from a nested struct and returns a flattened map
func extractConfigValues(config interface{}, parentKey string, result map[string]string) {
	v := reflect.ValueOf(config)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		key := field.Tag.Get("mapstructure")
		if key == "" {
			key = strings.ToLower(field.Name)
		}

		if parentKey != "" {
			key = parentKey + "." + key
		}

		// Handle different kinds of fields
		switch fieldValue.Kind() {
		case reflect.Struct:
			extractConfigValues(fieldValue.Interface(), key, result)
		case reflect.Ptr:
			if !fieldValue.IsNil() {
				extractConfigValues(fieldValue.Interface(), key, result)
			}
		case reflect.Slice, reflect.Array:
			// Convert slice elements to strings
			sliceValues := make([]string, fieldValue.Len())
			for j := 0; j < fieldValue.Len(); j++ {
				element := fieldValue.Index(j).Interface()
				sliceValues[j] = fmt.Sprintf("%v", element)
			}
			result[key] = "[" + strings.Join(sliceValues, ", ") + "]"
		default:
			result[key] = fmt.Sprintf("%v", fieldValue.Interface())
		}
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

func configMan(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Println("Please provide a configuration parameter name.")
		return
	}
	paramName := args[0]

	var matchedParam *docs.ParameterDoc
	for _, param := range docs.ParsedParameters {
		if strings.EqualFold(param.Name, paramName) {
			matchedParam = &param
			break
		}
	}

	if matchedParam == nil {
		fmt.Printf("No documentation found for parameter: %s\n", paramName)
		return
	}

	labelColor := color.New(color.FgGreen).Add(color.Bold)
	paramColor := color.New(color.FgCyan).Add(color.Bold)

	fmt.Println()
	fmt.Printf("%s %s\n", labelColor.Sprint("Parameter:"), paramColor.Sprint(matchedParam.Name))
	fmt.Printf("%s %s\n", labelColor.Sprint("Type:"), matchedParam.Type)
	fmt.Printf("%s %s\n", labelColor.Sprint("Default:"), formatValue(matchedParam.Default))
	fmt.Printf("%s\n\n", labelColor.Sprint("Description:"))
	fmt.Println(indentText(matchedParam.Description, "  "))
}

// func getCaseInsensitiveValueFromMap(m map[string]string, key string) (string, bool) {
// 	lowerKey := strings.ToLower(key)
// 	for k, v := range m {
// 		if strings.ToLower(k) == lowerKey {
// 			return v, true
// 		}
// 	}
// 	return "", false
// }

func formatValue(value interface{}) string {
	if value == nil {
		return "none"
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		var elements []string
		for i := 0; i < rv.Len(); i++ {
			elem := rv.Index(i).Interface()
			elements = append(elements, fmt.Sprintf("%v", elem))
		}
		return "[" + strings.Join(elements, ", ") + "]"
	case reflect.String:
		return fmt.Sprintf("%s", value)
	default:
		return fmt.Sprintf("%v", value)
	}
}

// indentText indents each line of the text with the given prefix
func indentText(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func init() {
	configCmd.AddCommand(configTestCmd)
	configCmd.AddCommand(configDumpCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configManCmd)
	configDumpCmd.Flags().StringVarP(&format, "format", "o", "yaml", "Output format (yaml or json)")
}
