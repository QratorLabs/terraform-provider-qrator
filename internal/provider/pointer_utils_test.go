package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestPtrInt64(t *testing.T) {
	t.Run("nil returns 0", func(t *testing.T) {
		if got := ptrInt64(nil); got != 0 {
			t.Errorf("ptrInt64(nil) = %d, want 0", got)
		}
	})

	t.Run("non-nil returns value", func(t *testing.T) {
		v := int64(42)
		if got := ptrInt64(&v); got != 42 {
			t.Errorf("ptrInt64(&42) = %d, want 42", got)
		}
	})
}

func TestOptionalInt64(t *testing.T) {
	t.Run("nil returns null", func(t *testing.T) {
		got := optionalInt64(nil)
		if !got.IsNull() {
			t.Errorf("optionalInt64(nil) should be null, got %v", got)
		}
	})

	t.Run("non-nil returns value", func(t *testing.T) {
		v := int64(99)
		got := optionalInt64(&v)
		if got.IsNull() || got.ValueInt64() != 99 {
			t.Errorf("optionalInt64(&99) = %v, want 99", got)
		}
	})
}

func TestOptionalBool(t *testing.T) {
	t.Run("nil returns null", func(t *testing.T) {
		got := optionalBool(nil)
		if !got.IsNull() {
			t.Errorf("optionalBool(nil) should be null, got %v", got)
		}
	})

	t.Run("true", func(t *testing.T) {
		v := true
		got := optionalBool(&v)
		if got.IsNull() || !got.ValueBool() {
			t.Errorf("optionalBool(&true) = %v, want true", got)
		}
	})

	t.Run("false", func(t *testing.T) {
		v := false
		got := optionalBool(&v)
		if got.IsNull() || got.ValueBool() {
			t.Errorf("optionalBool(&false) = %v, want false", got)
		}
	})
}

func TestBoolPtr(t *testing.T) {
	t.Run("null returns nil", func(t *testing.T) {
		got := boolPtr(types.BoolNull())
		if got != nil {
			t.Errorf("boolPtr(null) = %v, want nil", got)
		}
	})

	t.Run("unknown returns nil", func(t *testing.T) {
		got := boolPtr(types.BoolUnknown())
		if got != nil {
			t.Errorf("boolPtr(unknown) = %v, want nil", got)
		}
	})

	t.Run("true returns *true", func(t *testing.T) {
		got := boolPtr(types.BoolValue(true))
		if got == nil || !*got {
			t.Errorf("boolPtr(true) = %v, want *true", got)
		}
	})

	t.Run("false returns *false", func(t *testing.T) {
		got := boolPtr(types.BoolValue(false))
		if got == nil || *got {
			t.Errorf("boolPtr(false) = %v, want *false", got)
		}
	})
}
