# StopHookRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sandbox_id** | **String** |  | 
**sandbox_instance_id** | **String** | Identifier of the runtime instance being torn down: the value delivered by that instance's start-fresh / start-resume hook. May arrive after a newer start for the same sandboxId; ignore it when it does not match the latest started instance. | 
**filesystem_usage** | Option<[**models::FilesystemUsage**](FilesystemUsage.md)> |  | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


