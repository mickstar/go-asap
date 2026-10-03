package main

import "testing"

// TestDifferential is the committed, deterministic differential run. The seed is
// fixed so failures reproduce with the same iteration numbers; the claim and
// header offsets are chosen away from the 1s leeway boundary, so verdicts do not
// depend on wall-clock jitter.
func TestDifferential(t *testing.T) {
	rep := run(DefaultN, DefaultSeed)
	logReport(t, rep)

	if rep.Iterations < 2000 {
		t.Fatalf("only %d iterations; the committed test must exercise at least 2000", rep.Iterations)
	}
	if got := len(rep.Divergences); got != 0 {
		t.Fatalf("%d unexpected divergence(s); see the log for reproducers", got)
	}
	if rep.CrossMismatches != 0 {
		t.Fatalf("%d unexpected cross-library verdict mismatch(es)", rep.CrossMismatches)
	}
	// Guard the coverage of the documented divergences: if a refactor stops
	// producing them, the suite would otherwise pass while testing less.
	if rep.ExpectedECDSA == 0 {
		t.Fatal("no ECDSA signature-encoding divergence was exercised")
	}
	if rep.ExpectedPolicy == 0 {
		t.Fatal("no HS256/none policy divergence was exercised")
	}
	// Every algorithm in the matrix must appear.
	for _, alg := range allAlgs {
		if rep.AlgCount[alg] == 0 {
			t.Fatalf("algorithm %s was never exercised", alg)
		}
	}
}

// TestDifferentialSecondSeed widens coverage without pinning another full run.
func TestDifferentialSecondSeed(t *testing.T) {
	rep := run(500, 20261003)
	logReport(t, rep)
	if got := len(rep.Divergences); got != 0 {
		t.Fatalf("%d unexpected divergence(s) on the second seed", got)
	}
	if rep.CrossMismatches != 0 {
		t.Fatalf("%d unexpected cross-library verdict mismatch(es) on the second seed", rep.CrossMismatches)
	}
}

func logReport(t *testing.T, rep *report) {
	t.Helper()
	t.Logf("iterations=%d tokens=%d expectedECDSA=%d expectedPolicy=%d crossMismatches=%d divergences=%d",
		rep.Iterations, rep.Tokens, rep.ExpectedECDSA, rep.ExpectedPolicy, rep.CrossMismatches, len(rep.Divergences))
	for _, d := range rep.Divergences {
		t.Logf("DIVERGENCE iter=%d alg=%s mintedBy=%s kind=%s detail=%s\ntoken=%s\njoseErr=%s\nv2Err=%s",
			d.Iter, d.Alg, d.MintedBy, d.Kind, d.Detail, d.Token, d.JoseErr, d.V2Err)
	}
}
