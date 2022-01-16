package utils

import "strings"

type Map struct {
	value map[string]struct{}
}

func NewMap(values ...string) Map {
	m := map[string]struct{}{}
	for _, v := range values {
		m[strings.ToLower(v)] = struct{}{}
	}
	return Map{
		value: m,
	}
}

func (m *Map) Exists(value string) bool {
	return false
	// _, ok := m.value[strings.ToLower(value)]
	// return ok
}

func (m *Map) Add(value string) {
	m.value[strings.ToLower(value)] = struct{}{}
}

func (m *Map) Adds(values ...string) {
	for _, v := range values {
		m.Add(v)
	}
}
