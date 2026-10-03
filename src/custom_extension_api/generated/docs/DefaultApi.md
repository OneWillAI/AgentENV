# \DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**sandbox_filesystem_usage**](DefaultApi.md#sandbox_filesystem_usage) | **POST** /sandbox-hook/filesystem-usage | Best-effort ext4 usage observation triggered by root disk writes or flushes.
[**sandbox_patch_params**](DefaultApi.md#sandbox_patch_params) | **POST** /sandbox-hook/patch-params | Applies an extension-defined patch to a sandbox's custom extension params.
[**sandbox_start_fresh**](DefaultApi.md#sandbox_start_fresh) | **POST** /sandbox-hook/start-fresh | Invoked before a fresh sandbox boots, after its network slot is allocated.
[**sandbox_start_resume**](DefaultApi.md#sandbox_start_resume) | **POST** /sandbox-hook/start-resume | Invoked before a sandbox resumes from a snapshot, after its network slot is ready.
[**sandbox_stop**](DefaultApi.md#sandbox_stop) | **POST** /sandbox-hook/stop | Invoked when a sandbox stops, before its network resources are released.



## sandbox_filesystem_usage

> sandbox_filesystem_usage(filesystem_usage_hook_request)
Best-effort ext4 usage observation triggered by root disk writes or flushes.

No polling is required. On-disk ext4 counters may lag the mounted guest. Unknown usage is omitted, never reported as zero. Ignore observations from superseded runtime instances and non-increasing sequence numbers. Delivery failure never fails guest I/O. The stop hook includes a final observation when available, sampled after the VM process stops.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**filesystem_usage_hook_request** | [**FilesystemUsageHookRequest**](FilesystemUsageHookRequest.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## sandbox_patch_params

> models::PatchCustomExtensionParamsHookResponse sandbox_patch_params(patch_custom_extension_params_hook_request)
Applies an extension-defined patch to a sandbox's custom extension params.

Called when a user PATCHes the sandbox's custom extension params. The patch document is passed through verbatim; its semantics are defined entirely by the extension. The hook must return the updated full params, which the runtime stores as the new current value. A failure response rejects the patch: the sandbox keeps its previous params and the API call fails. The runtime does not serialize concurrent patches to the same sandbox; if patch semantics are not commutative, the extension must handle concurrency itself.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**patch_custom_extension_params_hook_request** | [**PatchCustomExtensionParamsHookRequest**](PatchCustomExtensionParamsHookRequest.md) |  | [required] |

### Return type

[**models::PatchCustomExtensionParamsHookResponse**](PatchCustomExtensionParamsHookResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## sandbox_start_fresh

> models::StartFreshHookResponse sandbox_start_fresh(start_fresh_hook_request)
Invoked before a fresh sandbox boots, after its network slot is allocated.

Called after the network slot is allocated and before the microVM is configured. The extension may return extra kernel boot args that are appended to the sandbox's boot args.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**start_fresh_hook_request** | [**StartFreshHookRequest**](StartFreshHookRequest.md) |  | [required] |

### Return type

[**models::StartFreshHookResponse**](StartFreshHookResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## sandbox_start_resume

> sandbox_start_resume(start_resume_hook_request)
Invoked before a sandbox resumes from a snapshot, after its network slot is ready.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**start_resume_hook_request** | [**StartResumeHookRequest**](StartResumeHookRequest.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## sandbox_stop

> sandbox_stop(stop_hook_request)
Invoked when a sandbox stops, before its network resources are released.

Called after the VM process is stopped but before the network slot is released. Fired whenever a sandbox runtime is torn down — including pause, which stops the VM process and releases the network namespace after the paused state is persisted (the subsequent resume creates a fresh runtime and fires start-resume). In-place pause+resume during snapshot capture does not fire this hook. Also sent best-effort (fire-and-forget) when a started sandbox is dropped without an explicit stop. Delivery failures are only logged by the runtime and never fail sandbox teardown.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**stop_hook_request** | [**StopHookRequest**](StopHookRequest.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

