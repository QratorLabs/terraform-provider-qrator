package provider

import (
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func listOf(vals ...string) types.List {
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, elems)
}

func emptyList() types.List {
	return types.ListValueMust(types.StringType, []attr.Value{})
}

func int64Ptr(v int64) *int64 {
	return &v
}

func boolPtrHelper(v bool) *bool {
	return &v
}

func strPtr(v string) *string {
	return &v
}

func rawMsg(v interface{}) *json.RawMessage {
	b, _ := json.Marshal(v)
	rm := json.RawMessage(b)
	return &rm
}
