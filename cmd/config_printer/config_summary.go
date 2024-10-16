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
	"fmt"
	"reflect"
	"strings"

	"github.com/pelicanplatform/pelican/docs"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func configSummary(cmd *cobra.Command, args []string) {
	rawConfig, _ := param.UnmarshalConfig()
	differences := make(map[string]interface{})
	getDifferencesRecursive(rawConfig, "", differences)
	yamlData, _ := yaml.Marshal(differences)
	fmt.Println(string(yamlData))

}

func getDifferencesRecursive(value interface{}, path string, differences map[string]interface{}) error {
	val := reflect.ValueOf(value)
	typ := reflect.TypeOf(value)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
		typ = typ.Elem()
	}

	switch val.Kind() {
	case reflect.Struct:
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			fieldType := typ.Field(i)

			fieldName := fieldType.Tag.Get("mapstructure")

			newPath := fieldName
			if path != "" {
				newPath = path + "." + fieldName
			}

			switch field.Kind() {
			case reflect.Struct, reflect.Ptr:
				subDifferences := make(map[string]interface{})
				err := getDifferencesRecursive(field.Interface(), newPath, subDifferences)
				if err != nil {
					return err
				}
				if len(subDifferences) > 0 {
					differences[fieldName] = subDifferences
				}
			default:
				docParam, ok := docs.ParsedParameters[newPath]
				if !ok {
					continue
				}
				defaultValueStr := formatFieldValueToCompare(reflect.ValueOf(docParam.Default))
				fieldValueStr := formatFieldValueToCompare(field)
				if defaultValueStr != fieldValueStr {
					differences[fieldName] = fmt.Sprintf("%v", field.Interface())

					// Structured and clear output for differences
					fmt.Printf("\n===========================\n")
					fmt.Printf("Field: %s\n", fieldName)
					fmt.Printf("---------------------------\n")
					fmt.Printf("Field value    : %s\n", fieldValueStr)
					fmt.Printf("Default value  : %s\n", defaultValueStr)
					fmt.Printf("===========================\n")
				}
			}
		}
	default:
	}

	return nil
}

func formatFieldValueToCompare(fieldValue reflect.Value) string {
	resultString := fmt.Sprintf("%v", fieldValue.Interface())
	resultString = strings.ReplaceAll(resultString, "none", "")
	resultString = strings.ReplaceAll(resultString, "0", "")
	resultString = strings.ReplaceAll(resultString, "[", "")
	resultString = strings.ReplaceAll(resultString, "]", "")
	resultString = strings.ReplaceAll(resultString, "<nil>", "")
	return resultString

}
