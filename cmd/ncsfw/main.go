package main

import (
	"github.com/n-creativesystem/ncsfw/logger"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "ncsfw",
		Short: "フレームワークで利用するコマンド集",
	}
	cmd.AddCommand(generateConfigCommand())
	if err := cmd.Execute(); err != nil {
		logger.Error(err, "コマンドエラー")
	}
}
