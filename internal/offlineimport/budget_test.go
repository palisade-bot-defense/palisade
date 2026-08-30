package offlineimport

import (
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func TestBudgetReaderExactBoundaryAndOneByteOver(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		budget := &budgets{maxInputBytes: 2}
		encoded, err := io.ReadAll(&budgetReader{reader: strings.NewReader("ab"), budget: budget})
		if err != nil || string(encoded) != "ab" || budget.inputBytes != 2 {
			t.Fatalf("exact boundary: bytes=%q count=%d err=%v", encoded, budget.inputBytes, err)
		}
	})
	t.Run("one over", func(t *testing.T) {
		budget := &budgets{maxInputBytes: 2}
		encoded, err := io.ReadAll(&budgetReader{reader: strings.NewReader("abc"), budget: budget})
		if !errors.Is(err, ErrInputByteBudget) || string(encoded) != "abc" || budget.inputBytes != 2 {
			t.Fatalf("over boundary: bytes=%q count=%d err=%v", encoded, budget.inputBytes, err)
		}
	})
}

func TestBudgetReaderMaxInt64DoesNotOverflow(t *testing.T) {
	budget := &budgets{maxInputBytes: math.MaxInt64, inputBytes: math.MaxInt64 - 1}
	reader := &budgetReader{reader: strings.NewReader("ab"), budget: budget}
	buffer := make([]byte, 2)
	n, err := reader.Read(buffer)
	if n != 1 || err != nil || budget.inputBytes != math.MaxInt64 {
		t.Fatalf("last allowed byte: n=%d count=%d err=%v", n, budget.inputBytes, err)
	}
	n, err = reader.Read(buffer)
	if n != 1 || !errors.Is(err, ErrInputByteBudget) || budget.inputBytes != math.MaxInt64 {
		t.Fatalf("overflow probe: n=%d count=%d err=%v", n, budget.inputBytes, err)
	}
}
