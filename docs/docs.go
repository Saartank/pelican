package docs

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	ParsedParameters map[string]*ParameterDoc
	//go:embed parameters.yaml
	parametersYaml []byte
)

type ParameterDoc struct {
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Default     interface{}         `yaml:"default"`
	Type        string              `yaml:"type"`
	Components  []string            `yaml:"components"`
	Deprecated  bool                `yaml:"deprecated"`
	Hidden      bool                `yaml:"hidden"`
	Tags        map[string]struct{} // Populated based on conditions
}

func init() {
	var err error
	ParsedParameters, err = parseParametersYAML()
	if err != nil {
		fmt.Printf("Error parsing parameters YAML: %v\n", err)
	}
}

func parseParametersYAML() (map[string]*ParameterDoc, error) {

	reader := bytes.NewReader(parametersYaml)

	parameters := make(map[string]*ParameterDoc)
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
			param.Tags = make(map[string]struct{})

			componentsToAdd := param.Components
			// Handle ["*"] in Components
			if len(param.Components) == 1 && param.Components[0] == "*" {
				componentsToAdd = []string{"origin", "cache", "registry", "director"}
				param.Components = []string{"origin", "cache", "registry", "director"}
			}

			for _, component := range componentsToAdd {
				param.Tags[strings.ToLower(component)] = struct{}{}
			}

			key := strings.ToLower(param.Name)
			parameters[key] = &param
		}
	}

	return parameters, nil
}
