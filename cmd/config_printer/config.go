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

	"github.com/spf13/cobra"

	_ "embed"
)

var (
	ConfigCmd = &cobra.Command{
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
		Use:     "describe",
		Short:   "Prints documentation for the config parameter matching best with the argument",
		Aliases: []string{"desc", "man", "doc"},
		Run:     configMan,
	}

	format string
	tags   []string
)

func configTest( /*cmd*/ *cobra.Command /*args*/, []string) {
	fmt.Println("You have run config Test!")
}

func init() {
	ConfigCmd.AddCommand(configTestCmd)
	ConfigCmd.AddCommand(configDumpCmd)
	ConfigCmd.AddCommand(configGetCmd)
	ConfigCmd.AddCommand(configManCmd)

	configDumpCmd.Flags().StringVarP(&format, "format", "o", "yaml", "Output format (yaml or json)")
	configGetCmd.Flags().StringArrayVarP(&tags, "tag", "t", []string{}, "Specify tags to filter output of config get (-t hidden -t origin)")
}
