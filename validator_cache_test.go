package asap

import (
	"context"
	"testing"
)

func TestValidatorCacheChainRunsAll(t *testing.T) {
	var counter = 0
	var validator = func(Token) error {
		counter++
		return nil
	}
	var v = NewCachingChainedASAPValidator(context.Background(), 100, validatorFunc(validator), validatorFunc(validator))
	var e = v.Validate(nil)
	if e != nil {
		t.Fatalf("Error testing validator chain: %s", e)
	}
	if counter != 2 {
		t.Fatalf("Expected 2 validator runs but saw %d", counter)
	}
}
