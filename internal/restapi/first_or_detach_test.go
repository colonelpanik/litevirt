package restapi

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestFirstOrDetach_ReturnsAPromptFirstMessage: the ordinary path must be
// untouched, or every migration would answer 202 and the caller would lose the
// first progress message it relies on.
func TestFirstOrDetach_ReturnsAPromptFirstMessage(t *testing.T) {
	want := &emptypb.Empty{}
	first, err, timedOut, rest := firstOrDetach(func() (proto.Message, error) {
		return want, nil
	})
	if timedOut {
		t.Fatal("a message that was ready immediately reported a timeout")
	}
	if err != nil || first != proto.Message(want) {
		t.Fatalf("first = %v, err = %v; want the message back", first, err)
	}
	if rest == nil {
		t.Fatal("the continuation must be usable for the detached reader")
	}
}

// TestFirstOrDetach_DoesNotDropTheFirstMessageOnTimeout is the property the
// obvious implementation gets wrong.
//
// When the ack times out the in-flight Recv is still running, and it owns the
// first message. Abandoning it would drop that message from the detached
// stream, so the operation's log would start at the second one. The
// continuation must deliver it before reading anything further.
func TestFirstOrDetach_DoesNotDropTheFirstMessageOnTimeout(t *testing.T) {
	prev := ackTimeoutForTest
	ackTimeoutForTest = 50 * time.Millisecond
	t.Cleanup(func() { ackTimeoutForTest = prev })

	slow := &emptypb.Empty{}
	second := errors.New("stream done")
	calls := 0
	_, _, timedOut, rest := firstOrDetach(func() (proto.Message, error) {
		calls++
		if calls == 1 {
			time.Sleep(200 * time.Millisecond)
			return slow, nil
		}
		return nil, second
	})
	if !timedOut {
		t.Fatal("a first message that took four times the ack budget did not time out")
	}

	got, err := rest()
	if err != nil || got != proto.Message(slow) {
		t.Fatalf("the detached reader got (%v, %v); the first message must not be dropped", got, err)
	}
	if _, err := rest(); !errors.Is(err, second) {
		t.Fatalf("the second read returned %v, want the stream's own next result", err)
	}
}
