package provider

import (
	"reflect"
	"strconv"
	"strings"
)

func itoa(p uint32) string { return strconv.FormatUint(uint64(p), 10) }

func stateFields() []string {
	t := reflect.TypeOf(State{})
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		out = append(out, name)
	}
	return out
}
