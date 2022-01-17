package utils

import "os"

func Getenv(key, default_ string) string {
	v := os.Getenv(key)
	if v == "" {
		return default_
	}
	return v
}
