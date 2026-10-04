package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The cluster's half of the "already a member" check for `lv host init`
// (colonelpanik/litevirt#229).
//
// refuseIfAlreadyAMember reads the target's own join_peers, and a founder's is
// empty: it was the first host, and `lv host add` run from a workstation has no
// local config to back-fill the new peer into. So pointing `lv host init` back
// at a founder whose disk was lost looks, from the target, exactly like
// re-running init on a half-finished first node, and is allowed. The rebuilt
// founder then mints an admin of its own. The receivers refuse that account
// (users_admin_guard.go), but the founder keeps serving it.
//
// The workstation running init can usually still see the cluster, though, and
// the cluster still lists the founder beside its peers. That is decisive: a
// half-finished first node is the ONLY host its cluster lists. The match is on
// address, not name: names like node-1 recur across clusters, and the CLI may
// be configured for a different one.
//
// No cluster to ask is what a genesis looks like from a workstation, so an
// unreachable or unreadable cluster does not block init. The target-side check
// and the daemon's own genesis gate still apply.

// clusterMemberCheckTimeout bounds the whole check. A genesis has no cluster
// to answer, and must not wait long to find that out.
const clusterMemberCheckTimeout = 10 * time.Second

// RefuseInitOfAClusterMember refuses `lv host init` against sshTarget when the
// cluster this CLI is configured for lists that address beside other hosts.
// force skips it, as it skips the target-side check.
func RefuseInitOfAClusterMember(ctx context.Context, sshTarget string, force bool) error {
	if force {
		return nil
	}
	host, _, err := parseSSHTarget(sshTarget)
	if err != nil {
		return nil // HostInit reports a bad target itself
	}
	addr, err := resolveHost(host)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, clusterMemberCheckTimeout)
	defer cancel()
	c, closer, err := Connect(ctx)
	if err != nil {
		slog.Debug("no cluster reachable to check the init target against", "error", err)
		return nil
	}
	defer closer()
	return refuseInitOfAClusterMember(ctx, c, addr)
}

func refuseInitOfAClusterMember(ctx context.Context, c pb.LiteVirtClient, hostAddr string) error {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		slog.Debug("could not list the cluster's hosts to check the init target against", "error", err)
		return nil
	}
	var match *pb.Host
	var others []string
	for _, h := range resp.GetHosts() {
		if h.GetAddress() == hostAddr {
			match = h
			continue
		}
		others = append(others, h.GetName())
	}
	if match == nil || len(others) == 0 {
		return nil
	}
	return fmt.Errorf("%s is %s, a member of the cluster this CLI is configured for, which "+
		"also lists %s. `lv host init` would re-initialise it as the first host of a cluster, "+
		"and a first host mints its own admin account. If its disk was lost, remove it "+
		"(`lv host rm %s`) and add it back (`lv host add`); re-run with --force to "+
		"re-initialise it anyway",
		hostAddr, match.GetName(), strings.Join(others, ", "), match.GetName())
}
