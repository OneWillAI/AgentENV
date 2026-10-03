# StartFreshHookRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sandbox_id** | **String** |  | 
**sandbox_instance_id** | **String** | Unique identifier of this runtime instance of the sandbox. A new value is generated for every start-fresh / start-resume; the subsequent stop hook carries the same value. | 
**network_namespace_path** | **String** | Host path of the sandbox's network namespace file (e.g. /var/run/netns/agentenv-ns-*). | 
**host_interaction_ip** | **String** | Per-runtime host interaction address routed to this sandbox. | 
**firecracker_pid** | Option<**i32**> | Firecracker process ID after the microVM process exists and before it is started. Present so the extension can place the VM in a lineage cgroup.  | [optional]
**custom_extension_params** | Option<**serde_json::Value**> | Opaque JSON object interpreted only by the custom extension. An absent value and an empty object are equivalent: both mean empty params. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


