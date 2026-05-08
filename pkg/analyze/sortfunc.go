package analyze

import (
	"fmt"
	"slices"

	"github.com/samber/lo"
)

type SortByFlag string

const (
	SortBySize        SortByFlag = "size"
	SortByRequests    SortByFlag = "requests"
	SortByDirectory   SortByFlag = "directory"
	SortByUserAgents  SortByFlag = "user-agents"
	SortByConnections SortByFlag = "connections"
)

func (s SortByFlag) String() string {
	return string(s)
}

func (s *SortByFlag) Set(value string) error {
	switch value {
	case "size":
		*s = SortBySize
	case "requests", "reqs":
		*s = SortByRequests
	case "directory", "dir":
		*s = SortByDirectory
	case string(SortByUserAgents), "ua", "uas":
		*s = SortByUserAgents
	case string(SortByConnections), "conns", "conn":
		*s = SortByConnections
	default:
		return fmt.Errorf("must be one of: %v", ListSortFuncs())
	}
	return nil
}

func (s SortByFlag) Type() string {
	return "string"
}

type SortFunc func(l, r StatKey) int

var sortFuncs = map[SortByFlag]func(a map[StatKey]IPStats) SortFunc{
	SortBySize: func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return int(i[r].Size - i[l].Size)
		}
	},
	SortByRequests: func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return int(i[r].Requests - i[l].Requests)
		}
	},
	SortByUserAgents: func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return len(i[r].UAStore) - len(i[l].UAStore)
		}
	},
	SortByConnections: func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return int(i[r].Connections - i[l].Connections)
		}
	},
}

func GetSortFunc(name SortByFlag, i map[StatKey]IPStats) SortFunc {
	fn, ok := sortFuncs[name]
	if !ok {
		return nil
	}
	return fn(i)
}

func ListSortFuncs() []SortByFlag {
	ret := lo.Keys(sortFuncs)
	slices.Sort(ret)
	return ret
}
