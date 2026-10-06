package scheduler

import (
	schedulerv1 "agentenv/services/api/proto"
	"agentenv/services/shared/config"
)

// WithPlacement enables opt-in, hard node selection through existing request
// metadata. Authentication and authorization of the selector belong to the
// trusted caller; this option must not be exposed to untrusted create traffic.
func WithPlacement(placement *config.PlacementConfig) ServiceOption {
	return func(s *Service) { s.placement = placement }
}

func filterPlacement(nodes []RichNode, hint *schedulerv1.ScheduleRequestHint, placement *config.PlacementConfig) []RichNode {
	if placement == nil {
		return nodes
	}
	var metadata map[string]string
	if cold := hint.GetNewColdSandbox(); cold != nil {
		metadata = cold.GetMetadata()
	} else if warm := hint.GetNewSandbox(); warm != nil {
		metadata = warm.GetMetadata()
	}
	selected, explicit := metadata[placement.MetadataKey]
	allowed := make(map[string]bool)
	if explicit {
		// An empty or unknown explicit selector fails closed.
		if selected != "" {
			allowed[selected] = true
		}
	} else {
		for _, id := range placement.DefaultNodeIDs {
			allowed[id] = true
		}
	}
	result := make([]RichNode, 0, len(nodes))
	for _, node := range nodes {
		if allowed[node.ID] && (!placement.RequireReady || node.Snapshot.GetStatus() == schedulerv1.NodeStatus_NODE_STATUS_READY) {
			result = append(result, node)
		}
	}
	return result
}
