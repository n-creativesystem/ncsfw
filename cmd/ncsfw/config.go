package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	//go:embed config_base.yaml
	config []byte
)

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func generateConfigCommand() *cobra.Command {
	cmd := cobra.Command{
		Use: "config",
		RunE: func(cmd *cobra.Command, args []string) error {
			v := viper.New()
			v.SetConfigType("yaml")
			if err := v.ReadConfig(bytes.NewBuffer(config)); err != nil {
				return err
			}
			flags := cmd.Flags()
			ext, err := flags.GetString("ext")
			if err != nil {
				return err
			}
			filename := fmt.Sprintf("config.%s", strings.TrimPrefix(ext, "."))
			if exists(filename) {
				ext := path.Ext(filename)
				baseName := strings.TrimSuffix(path.Base(filename), ext)
				if err := os.Rename(filename, fmt.Sprintf("%s_%s%s", baseName, "old", ext)); err != nil {
					return err
				}
			}
			return v.WriteConfigAs(filename)
		},
	}
	flags := cmd.Flags()
	flags.String("ext", "yaml", "generation config file type(yaml, yml, json, toml, hcl, tfvars, prop, props, properties, dotenv, env, ini)")
	return &cmd
}
