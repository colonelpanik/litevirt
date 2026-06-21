package network

import (
	"testing"
)

func TestAddFDBEntry(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := AddFDBEntry(100, "aa:bb:cc:dd:ee:ff", "192.168.1.2")
	if err != nil {
		t.Fatalf("AddFDBEntry: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	exp := []string{"bridge", "fdb", "add", "aa:bb:cc:dd:ee:ff", "dev", "vxlan100", "dst", "192.168.1.2"}
	if len(calls[0]) != len(exp) {
		t.Fatalf("expected %v, got %v", exp, calls[0])
	}
	for i, a := range exp {
		if calls[0][i] != a {
			t.Errorf("arg %d: expected %q, got %q", i, a, calls[0][i])
		}
	}
}

func TestDeleteFDBEntry(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := DeleteFDBEntry(200, "11:22:33:44:55:66", "10.0.0.5")
	if err != nil {
		t.Fatalf("DeleteFDBEntry: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	exp := []string{"bridge", "fdb", "del", "11:22:33:44:55:66", "dev", "vxlan200", "dst", "10.0.0.5"}
	for i, a := range exp {
		if calls[0][i] != a {
			t.Errorf("arg %d: expected %q, got %q", i, a, calls[0][i])
		}
	}
}

func TestFloodEntry(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := FloodEntry(300, "172.16.0.1")
	if err != nil {
		t.Fatalf("FloodEntry: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	exp := []string{"bridge", "fdb", "add", "00:00:00:00:00:00", "dev", "vxlan300", "dst", "172.16.0.1"}
	for i, a := range exp {
		if calls[0][i] != a {
			t.Errorf("arg %d: expected %q, got %q", i, a, calls[0][i])
		}
	}
}

func TestDeleteFloodEntry(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := DeleteFloodEntry(400, "172.16.0.2")
	if err != nil {
		t.Fatalf("DeleteFloodEntry: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	exp := []string{"bridge", "fdb", "del", "00:00:00:00:00:00", "dev", "vxlan400", "dst", "172.16.0.2"}
	for i, a := range exp {
		if calls[0][i] != a {
			t.Errorf("arg %d: expected %q, got %q", i, a, calls[0][i])
		}
	}
}
