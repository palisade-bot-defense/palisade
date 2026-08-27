package shadowanalysis

import "math"

const confidenceZ95 = 1.959963984540054

// Proportion returns the observed proportion and a Wilson score interval at
// 95% confidence. It describes aggregate uncertainty; it does not establish
// causality or convert an outcome label mix into a false-positive rate.
func Proportion(count, total uint64) ProportionEstimate {
	result := ProportionEstimate{Count: count, Total: total}
	if total == 0 || count > total {
		return result
	}
	n := float64(total)
	p := float64(count) / n
	z2 := confidenceZ95 * confidenceZ95
	denominator := 1 + z2/n
	center := (p + z2/(2*n)) / denominator
	margin := confidenceZ95 * math.Sqrt((p*(1-p)+z2/(4*n))/n) / denominator
	result.Rate = p
	result.Lower95 = maximum(0, center-margin)
	result.Upper95 = minimum(1, center+margin)
	return result
}

// ProportionDifference returns the observed difference and a conservative 95%
// interval obtained from the two Wilson intervals.
func ProportionDifference(left, right ProportionEstimate) DifferenceEstimate {
	return DifferenceEstimate{
		Estimate: left.Rate - right.Rate,
		Lower95:  maximum(-1, left.Lower95-right.Upper95),
		Upper95:  minimum(1, left.Upper95-right.Lower95),
	}
}

func validProportion(value ProportionEstimate) bool {
	expected := Proportion(value.Count, value.Total)
	return value.Count <= value.Total && closeRatio(value.Rate, expected.Rate) && closeRatio(value.Lower95, expected.Lower95) && closeRatio(value.Upper95, expected.Upper95) &&
		value.Lower95 <= value.Rate && value.Rate <= value.Upper95
}

func validDifference(value DifferenceEstimate, left, right ProportionEstimate) bool {
	expected := ProportionDifference(left, right)
	return finiteBounded(value.Estimate, -1, 1) && finiteBounded(value.Lower95, -1, 1) && finiteBounded(value.Upper95, -1, 1) &&
		value.Lower95 <= value.Estimate && value.Estimate <= value.Upper95 && closeRatio(value.Estimate, expected.Estimate) &&
		closeRatio(value.Lower95, expected.Lower95) && closeRatio(value.Upper95, expected.Upper95)
}

func finiteBounded(value, lower, upper float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= lower && value <= upper
}

func maximum(left, right float64) float64 {
	if left > right {
		return left
	}
	return right
}
