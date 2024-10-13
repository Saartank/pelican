package config_printer

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/fatih/color"
	"github.com/pelicanplatform/pelican/docs"
	"github.com/spf13/cobra"
)

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
