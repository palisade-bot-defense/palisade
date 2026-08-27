package shadowanalysis

import (
	"math"
	"testing"
)

func TestWilsonProportionInterval(t *testing.T) {
	estimate := Proportion(5, 10)
	if estimate.Rate != 0.5 || math.Abs(estimate.Lower95-0.236593090512564) > 1e-12 || math.Abs(estimate.Upper95-0.763406909487436) > 1e-12 {
		t.Fatalf("unexpected Wilson interval: %+v", estimate)
	}
	if empty := Proportion(0, 0); empty != (ProportionEstimate{}) || !validProportion(empty) {
		t.Fatalf("empty proportion = %+v", empty)
	}
	if invalid := Proportion(2, 1); validProportion(invalid) {
		t.Fatalf("invalid proportion accepted: %+v", invalid)
	}
}

func TestConservativeDifferenceInterval(t *testing.T) {
	canary := Proportion(20, 100)
	shadow := Proportion(10, 100)
	difference := ProportionDifference(canary, shadow)
	if math.Abs(difference.Estimate-0.1) > 1e-12 || difference.Lower95 > difference.Estimate || difference.Upper95 < difference.Estimate || !validDifference(difference, canary, shadow) {
		t.Fatalf("invalid difference interval: %+v", difference)
	}
}
