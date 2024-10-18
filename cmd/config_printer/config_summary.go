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

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/docs"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func CompareStructsAsym(v1, v2 interface{}) interface{} {
	// Get the reflect.Value of both inputs
	val1 := reflect.ValueOf(v1)
	val2 := reflect.ValueOf(v2)

	// Handle pointers
	if val1.Kind() == reflect.Ptr {
		val1 = val1.Elem()
	}
	if val2.Kind() == reflect.Ptr {
		val2 = val2.Elem()
	}

	// Initialize the diff variable
	var diff interface{}

	switch val1.Kind() {
	case reflect.Struct:
		diffMap := make(map[string]interface{})
		typeOfVal1 := val1.Type()
		for i := 0; i < val1.NumField(); i++ {
			fieldName := typeOfVal1.Field(i).Name
			fieldVal1 := val1.Field(i).Interface()

			// Get the corresponding field in val2
			var fieldVal2 interface{}
			if val2.IsValid() {
				fieldVal2 = val2.FieldByName(fieldName).Interface()
			} else {
				fieldVal2 = nil
			}

			// Recursively compare the fields
			fieldDiff := CompareStructsAsym(fieldVal1, fieldVal2)
			if fieldDiff != nil {
				diffMap[fieldName] = fieldDiff
			}
		}
		if len(diffMap) > 0 {
			diff = diffMap
		}

	case reflect.Map:
		diffMap := make(map[interface{}]interface{})
		for _, key := range val1.MapKeys() {
			val1Elem := val1.MapIndex(key).Interface()
			var val2Elem interface{}
			if val2.IsValid() {
				val2Elem = val2.MapIndex(key).Interface()
			} else {
				val2Elem = nil
			}
			elemDiff := CompareStructsAsym(val1Elem, val2Elem)
			if elemDiff != nil {
				diffMap[key.Interface()] = elemDiff
			}
		}
		if len(diffMap) > 0 {
			diff = diffMap
		}

	case reflect.Slice, reflect.Array:
		if !reflect.DeepEqual(v1, v2) {
			diff = v1
		}

	default:
		if !reflect.DeepEqual(v1, v2) {
			diff = v1
		}
	}

	return diff
}

func CompareConfigsAsymOld(cfg1, cfg2 map[string]interface{}) map[string]interface{} {
	diff := make(map[string]interface{})

	for key, val1 := range cfg1 {
		val2, exists := cfg2[key]
		if !exists {
			// Key exists in cfg1 but not in cfg2, include it in diff
			diff[key] = val1
		} else {
			switch v1 := val1.(type) {
			case map[string]interface{}:
				if v2, ok := val2.(map[string]interface{}); ok {
					// Recursively compare nested maps
					nestedDiff := CompareConfigsAsymOld(v1, v2)
					if len(nestedDiff) > 0 {
						diff[key] = nestedDiff
					}
				} else {
					// Type mismatch, include val1 in diff
					diff[key] = val1
				}
			default:
				if !reflect.DeepEqual(val1, val2) {
					// Values are different, include val1 in diff
					diff[key] = val1
				}
				// Else values are the same, do not include in diff
			}
		}
	}

	return diff
}

func PrintViperConfig(v *viper.Viper) {
	configMap := v.AllSettings()

	// Pretty print the map
	for key, value := range configMap {
		fmt.Printf("%s: %v\n", key, value)
	}
}

func configSummary(cmd *cobra.Command, args []string) {
	defaultConfig := viper.New()
	config.InitConfigCustom(defaultConfig)
	defaultConfigMap := PopulateConfig(defaultConfig)

	currentConfigMap := PopulateConfig(viper.GetViper())

	fmt.Println("=================================")
	fmt.Println("Orginal with default reference: ")
	diff := CompareStructsAsym(currentConfigMap, defaultConfigMap)

	diffYaml, err := yaml.Marshal(diff)
	if err != nil {
		fmt.Printf("Error marshalling diff to YAML: %v\n", err)
		return
	}
	fmt.Println("Difference in YAML format:")
	fmt.Println(string(diffYaml))

	fmt.Println("=================================")
	fmt.Println("Default with original as reference: ")

	diff = CompareStructsAsym(defaultConfigMap, currentConfigMap)

	diffYaml, err = yaml.Marshal(diff)
	if err != nil {
		fmt.Printf("Error marshalling diff to YAML: %v\n", err)
		return
	}
	fmt.Println("Difference in YAML format:")
	fmt.Println(string(diffYaml))
}

func configSummaryOld(cmd *cobra.Command, args []string) {
	rawConfig, _ := param.UnmarshalConfig()
	differences := make(map[string]interface{})
	getDifferencesRecursive(rawConfig, "", differences)
	yamlData, _ := yaml.Marshal(differences)
	fmt.Println(string(yamlData))

	fmt.Println("----------------------------------------")
	fmt.Println("rawConfig.Director.AdvertisementTTL", rawConfig.Director.AdvertisementTTL)

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
					fmt.Printf("Field: %s\n", newPath)
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
	return resultString

}
