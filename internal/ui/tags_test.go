package ui

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestParseTags(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]string
	}{
		{"", nil},
		{"  ", nil},
		{"gpu", map[string]string{"gpu": ""}},
		{"env=prod, team=infra", map[string]string{"env": "prod", "team": "infra"}},
		{"a , =noKey , b=2 ", map[string]string{"a": "", "b": "2"}},
	}
	for _, c := range cases {
		if got := parseTags(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseTags(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
	// Round-trips through labelsToString (stable order).
	if got := labelsToString(map[string]string{"team": "infra", "env": "prod", "gpu": ""}); got != "env=prod, gpu, team=infra" {
		t.Errorf("labelsToString = %q", got)
	}
}

func TestVMTagsFlow(t *testing.T) {
	t.Run("create posts parsed labels", func(t *testing.T) {
		mock := newDefaultMock()
		s := newTestUIServer(t, mock)
		r := ctPost(t, "/ui/vms", "name=tagged&image=ubuntu&cpu=2&memory=2048&tags=env=prod, gpu")
		w := serveRequest(s, withAuth(r))
		assertStatus(t, w, http.StatusOK)
		got := mock.lastCreateVMReq.Spec.Labels
		if got["env"] != "prod" || got["gpu"] != "" {
			t.Errorf("spec.Labels = %#v", got)
		}
	})

	t.Run("tags modal prefills current labels", func(t *testing.T) {
		mock := newDefaultMock()
		mock.inspectVMResp = &pb.VM{Name: "vm1", State: pb.VMState_VM_RUNNING, HostName: "host1",
			Spec: &pb.VMSpec{Labels: map[string]string{"env": "prod"}}}
		s := newTestUIServer(t, mock)
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/tags-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), `name="tags"`, "env=prod", "/ui/vms/vm1/tags")
	})

	t.Run("set tags calls SetVMLabels + redirects", func(t *testing.T) {
		mock := newDefaultMock()
		s := newTestUIServer(t, mock)
		w := serveRequest(s, withAuth(ctPost(t, "/ui/vms/vm1/tags", "tags=env=staging, web")))
		assertStatus(t, w, http.StatusOK)
		if w.Header().Get("HX-Redirect") != "/vms/vm1" {
			t.Errorf("HX-Redirect = %q", w.Header().Get("HX-Redirect"))
		}
		req := mock.lastSetLabelsVMReq
		if req == nil || req.Labels["env"] != "staging" || req.Labels["web"] != "" {
			t.Errorf("SetVMLabels req = %#v", req)
		}
	})

	t.Run("detail renders chips + edit button", func(t *testing.T) {
		mock := newDefaultMock()
		mock.inspectVMResp = &pb.VM{Name: "vm1", State: pb.VMState_VM_RUNNING, HostName: "host1",
			Spec: &pb.VMSpec{Labels: map[string]string{"env": "prod"}}}
		s := newTestUIServer(t, mock)
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/vms/vm1")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		if !strings.Contains(body, `class="tag"`) || !strings.Contains(body, "env") {
			t.Error("detail page missing tag chips")
		}
		mustContain(t, body, "/ui/vms/vm1/tags-modal")
	})
}
