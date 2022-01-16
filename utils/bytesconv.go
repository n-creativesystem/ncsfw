package utils

import (
	"encoding/base64"
	"unsafe"
)

func StringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func BytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Base64ToByte(b string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b)
}
