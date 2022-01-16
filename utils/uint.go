package utils

import "strconv"

func ParseUint64(val string) (uint64, error) {
	return strconv.ParseUint(val, 0, 64)
}

func Str2Uint64(val string, default_ uint64) uint64 {
	if v, err := strconv.ParseUint(val, 0, 64); err != nil {
		return default_
	} else {
		return v
	}
}

func Str2Uint32(val string, default_ uint32) uint32 {
	if v, err := strconv.ParseUint(val, 10, 32); err != nil {
		return default_
	} else {
		return uint32(v)
	}
}
