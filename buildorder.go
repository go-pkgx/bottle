package bottle

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Ordering the builds of one version.
//
// ⛔⛔ THERE IS NO BUILD DATE, AND THAT IS A DELIBERATE PROPERTY RATHER THAN A
// GAP TO FILL. A published bottle's timestamp is PINNED — `bk factory` stamps
// SOURCE_DATE_EPOCH, or its own fixed epoch when that is unset, never the
// wall clock — so that re-publishing the same bottle yields byte-identical
// attestations and the same referrer digests. Every bottle the factory
// publishes therefore carries the SAME instant, and sorting by it would order
// a list by a constant while looking like it ordered by time.
//
// Taking the wall clock instead would trade that for an ordering nobody
// needs: it would make every rebuild a new artefact and break the idempotent
// re-push. So the date is not recoverable from a bottle, by construction, and
// a reader asking "which is the newest" has to be answered with something
// that was actually written down.
//
// ⛔ AND ORDER IS A PRESENTATION QUESTION, NOT A RESOLUTION ONE. The resolver
// still refuses an ambiguous version: two builds of one version are siblings,
// and nothing here gives it permission to pick. What this orders is a LIST a
// person reads, and every key below is a recorded fact that the listing names
// out loud — never an inference dressed up as one.
type BuildOrder string

const (
	// ByStatus is the default: the builds that nothing is wrong with first,
	// the withdrawn ones last, each group by hash so the order is stable.
	//
	// It is the only key derived from a judgement, and the judgement was
	// made by a person and written in the withdrawal list — not by us.
	ByStatus BuildOrder = "status"
	// ByHash is the stable, meaningless order: what a script wants, and what
	// two runs are guaranteed to agree on.
	ByHash BuildOrder = "hash"
	// ByInstalled is most recently installed HERE first, then the ones that
	// are not installed at all.
	//
	// ⛔ IT IS A FACT ABOUT THIS MACHINE AND THE LISTING MUST SAY SO. It is
	// when you got the build, not when it was built, and the two are
	// unrelated: pulling a two-year-old bottle today puts it first.
	ByInstalled BuildOrder = "installed"
)

// BuildOrders lists the keys, for a flag's help and for validating one.
var BuildOrders = []BuildOrder{ByStatus, ByHash, ByInstalled}

// ParseBuildOrder reads a sort key, naming the alternatives when it cannot.
func ParseBuildOrder(s string) (BuildOrder, error) {
	for _, o := range BuildOrders {
		if string(o) == s {
			return o, nil
		}
	}
	names := make([]string, 0, len(BuildOrders))
	for _, o := range BuildOrders {
		names = append(names, string(o))
	}
	return "", fmt.Errorf("%q is not a sort key (have: %s)", s, strings.Join(names, ", "))
}

// SortBuilds orders builds in place and returns them.
//
// ⛔ EVERY KEY FALLS BACK TO THE HASH. Without it two builds that tie on the
// key keep whatever order they arrived in, which is a map walk — so the same
// command would print a different list twice and a reader would stop
// believing either.
func SortBuilds(project string, builds []Build, by BuildOrder) []Build {
	sort.SliceStable(builds, func(i, j int) bool {
		a, b := builds[i], builds[j]
		switch by {
		case ByInstalled:
			if a.InstalledAt != b.InstalledAt {
				// Not installed sorts last, whatever the zero time would do.
				switch {
				case a.InstalledAt.IsZero():
					return false
				case b.InstalledAt.IsZero():
					return true
				}
				return a.InstalledAt.After(b.InstalledAt)
			}
		case ByStatus:
			aw, bw := isWithdrawn(project, a), isWithdrawn(project, b)
			if aw != bw {
				return bw
			}
		}
		return a.Hash() < b.Hash()
	})
	return builds
}

func isWithdrawn(project string, b Build) bool {
	_, yes := WithdrawalOf(project, b.Version.Raw, b.Hash())
	return yes
}

// installedAt is when a build's directory appeared in this store, or the zero
// time when it is not installed.
//
// ⛔ THE DIRECTORY'S OWN MODIFICATION TIME, NOT A FILE INSIDE IT. A bottle's
// files carry the timestamps the archive recorded, which the publisher pinned
// for reproducibility — so reading one would report the pinned epoch and
// call it an install date.
func installedAt(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// WhyNoDate is the one line a command prints when a reader asks for an order
// by build date, so the absence is explained rather than looking like an
// oversight.
const WhyNoDate = "there is no build date: a published bottle's timestamp is pinned " +
	"(SOURCE_DATE_EPOCH) so that re-publishing it is byte-identical, which means every " +
	"bottle carries the same instant. --sort=installed orders by when THIS machine got them."
