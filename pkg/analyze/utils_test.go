package analyze

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func assertAdjacentPrefix(t *testing.T, p1, p2 string) {
	assert.Equal(t, netip.MustParsePrefix(p2), AdjacentPrefix(netip.MustParsePrefix(p1)))
	assert.Equal(t, netip.MustParsePrefix(p1), AdjacentPrefix(netip.MustParsePrefix(p2)))
}

func TestAdjacentPrefix(t *testing.T) {
	assertAdjacentPrefix(t, "1.2.3.0/24", "1.2.2.0/24")
	assertAdjacentPrefix(t, "1.2.2.0/23", "1.2.0.0/23")
	assertAdjacentPrefix(t, "2001:db8:114:514::/64", "2001:db8:114:515::/64")
	assertAdjacentPrefix(t, "2001:db8:114:514::/63", "2001:db8:114:516::/63")
}