package main

import (
	"encoding/json"
	"testing"
)

func TestValidateMessagePreservesID(t *testing.T) {
	input := []byte(`{"jsonrpc":"2.0","id":"request-42","method":"tools/call","params":{"name":"filesystem.read_file"},"x-extension":{"safe":true}}`)
	message, err := validateMessage(input, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if err := json.Unmarshal(message.ID, &id); err != nil || id != "request-42" {
		t.Fatalf("request ID changed: %s", message.ID)
	}
}

func TestRejectsMalformedAndOversizedMessages(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"jsonrpc":"1.0","method":"ping"}`),
		[]byte(`{"jsonrpc":"2.0"}`),
		[]byte(`not-json`),
	}
	for _, input := range cases {
		if _, err := validateMessage(input, 1024); err == nil {
			t.Fatalf("expected rejection: %q", input)
		}
	}
	if _, err := validateMessage([]byte(`{"jsonrpc":"2.0","method":"ping"}`), 4); err == nil {
		t.Fatal("expected payload limit rejection")
	}
}

func TestRewriteParamsPreservesExtensions(t *testing.T) {
	input := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"},"vendor":{"trace":"yes"}}`)
	output, err := rewriteParams(input, map[string]any{"name": "safe"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["vendor"].(map[string]any)["trace"] != "yes" {
		t.Fatal("safe extension field was dropped")
	}
}
