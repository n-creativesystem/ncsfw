package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUintConv(t *testing.T) {
	t1 := Str2Uint64("10", 0)
	assert.Equal(t, uint64(10), t1)
	t2 := Str2Uint32("10", 0)
	assert.Equal(t, uint32(10), t2)

	t3 := Str2Uint64("aaa", 0)
	assert.Equal(t, uint64(0), t3)
	t4 := Str2Uint32("aaa", 0)
	assert.Equal(t, uint32(0), t4)
}
