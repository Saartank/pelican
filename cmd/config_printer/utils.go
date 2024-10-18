package config_printer

import (
	"fmt"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
)

func PopulateConfig(v *viper.Viper) *param.Config {
	config.InitServerCustom(v)
	config.InitClientCustom(v)

	exapandedConfig, err := param.UnmarshalConfigCustom(v)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return exapandedConfig

}
