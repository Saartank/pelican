package docs

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

var (
	ParsedParameters []ParameterDoc
	//go:embed parameters.yaml
	parametersYaml []byte
)

type ParameterDoc struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Default     interface{} `yaml:"default"`
	Components  []string    `yaml:"components"`
	Type        string      `yaml:"type"`
}

func init() {
	var err error
	ParsedParameters, err = parseParametersYAML()
	if err != nil {
		fmt.Printf("Error parsing parameters YAML: %v\n", err)
	}
}

func parseParametersYAML() ([]ParameterDoc, error) {

	reader := bytes.NewReader(parametersYaml)

	var parameters []ParameterDoc
	decoder := yaml.NewDecoder(reader)
	for {
		var param ParameterDoc
		err := decoder.Decode(&param)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse parameters file: %v", err)
		}
		if param.Name != "" {
			parameters = append(parameters, param)
		}
	}

	return parameters, nil
}
