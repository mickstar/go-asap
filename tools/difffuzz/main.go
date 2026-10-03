// Command difffuzz differentially fuzzes the migrated asap v2 module against
// jose, the JWT library it replaced.
//
// Run it from this directory on the Go 1.26 toolchain, because jose panics at
// init on Go 1.27:
//
//	GOTOOLCHAIN=go1.26.0 go run . -n 20000 -seed 1
//
// It exits non-zero and prints one JSON reproducer per unexpected divergence.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

func main() {
	n := flag.Int("n", DefaultN, "number of seeded fuzz iterations")
	seed := flag.Int64("seed", DefaultSeed, "PRNG seed; the same seed always exercises the same cases")
	flag.Parse()

	rep := run(*n, *seed)
	printReport(os.Stdout, rep)
	if len(rep.Divergences) > 0 {
		os.Exit(1)
	}
}

func printReport(out *os.File, rep *report) {
	algs := make([]string, 0, len(rep.AlgCount))
	for alg := range rep.AlgCount {
		algs = append(algs, alg)
	}
	sort.Strings(algs)

	fmt.Fprintf(out, "difffuzz: %d iterations, %d tokens evaluated (seed %d)\n",
		rep.Iterations, rep.Tokens, rep.Seed)
	for _, alg := range algs {
		fmt.Fprintf(out, "  %-6s %d\n", alg, rep.AlgCount[alg])
	}
	fmt.Fprintf(out, "expected divergences: ES* signature encoding=%d, HS256/none policy=%d, unresolvable kid=%d\n",
		rep.ExpectedECDSA, rep.ExpectedPolicy, rep.ExpectedUnresolvableKid)
	fmt.Fprintf(out, "unexpected cross-library verdict mismatches: %d\n", rep.CrossMismatches)
	fmt.Fprintf(out, "time-boundary verdicts skipped: %d\n", rep.TimeBoundarySkipped)
	fmt.Fprintf(out, "unexpected divergences: %d\n", len(rep.Divergences))

	if len(rep.Divergences) == 0 {
		return
	}
	fmt.Fprintln(out, "reproducers:")
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	for _, d := range rep.Divergences {
		_ = enc.Encode(d)
	}
}
