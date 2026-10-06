package scheduler

import (
	"context"
	"testing"
	"time"

	schedulerv1 "agentenv/services/api/proto"
	"agentenv/services/shared/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPlacementIsExclusiveAndRequiresLiveHeartbeat(t *testing.T) {
	registry := NewAtomicNodeRegistry([]Node{{ID: "general", Endpoint: "http://general"}, {ID: "private", Endpoint: "http://private"}}, time.Minute)
	svc := NewService(nil, registry, &RoundRobinStrategy{}, nil, WithPlacement(&config.PlacementConfig{
		MetadataKey: "destination", DefaultNodeIDs: []string{"general"}, RequireReady: true,
	}))
	for _, id := range []string{"general", "private"} {
		_, _, err := registry.Heartbeat(&schedulerv1.HeartbeatRequest{NodeId: id, ServiceInstanceId: id,
			Snapshot: &schedulerv1.NodeSnapshot{Status: schedulerv1.NodeStatus_NODE_STATUS_READY}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, selected, want string
		explicit             bool
	}{
		{name: "ordinary", want: "general"},
		{name: "dedicated", selected: "private", explicit: true, want: "private"},
		{name: "unknown", selected: "missing", explicit: true},
		{name: "empty", explicit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cold := range []bool{false, true} {
				metadata := map[string]string{}
				if tc.explicit {
					metadata["destination"] = tc.selected
				}
				hint := &schedulerv1.ScheduleRequestHint{Kind: &schedulerv1.ScheduleRequestHint_NewSandbox{NewSandbox: &schedulerv1.NewSandboxHint{Metadata: metadata}}}
				if cold {
					hint.Kind = &schedulerv1.ScheduleRequestHint_NewColdSandbox{NewColdSandbox: &schedulerv1.NewColdSandboxHint{Metadata: metadata}}
				}
				for i := 0; i < 4; i++ {
					response, err := svc.Schedule(context.Background(), &schedulerv1.ScheduleRequest{Hint: hint})
					if tc.want == "" {
						if status.Code(err) != codes.Unavailable {
							t.Fatalf("expected unavailable, got %v", err)
						}
					} else if err != nil || response.GetNode().GetNodeId() != tc.want {
						t.Fatalf("response=%v error=%v", response, err)
					}
				}
			}
		})
	}
	// Keep a ready dedicated worker, but expire the general worker heartbeat.
	_, _, err := registry.Heartbeat(&schedulerv1.HeartbeatRequest{NodeId: "general", ServiceInstanceId: "general",
		Snapshot: &schedulerv1.NodeSnapshot{Status: schedulerv1.NodeStatus_NODE_STATUS_READY}}, time.Now().Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Schedule(context.Background(), &schedulerv1.ScheduleRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("ordinary traffic must not spill onto dedicated: %v", err)
	}
}
