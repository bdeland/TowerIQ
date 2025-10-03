# Test Report

**Total:** 119 **Passed:** 98 **Failed:** 21 **Skipped:** 0

> Source files: `_reports\junit\pytest.xml`

## Failures (21)

### 1. test_get_frida_server_binary_download
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerBinaryManagement`
- **Suite:** `pytest`
- **Trace hint:** `C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:81: in test_get_frida_server_binary_download`

**Message**

TypeError: 'coroutine' object does not support the asynchronous context manager protocol

<details><summary>Stack / Details</summary>

```
C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:81: in test_get_frida_server_binary_download
    result = await manager._get_frida_server_binary("arm64-v8a", "15.2.2")
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
C:\Users\delan\Documents\GitHub\TowerIQ\src\tower_iq\services\frida_manager.py:86: in _get_frida_server_binary
    async with session.get(url) as response:
E   TypeError: 'coroutine' object does not support the asynchronous context manager protocol
```
</details>

### 2. test_push_to_device_alternative_method
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerDeviceOperations`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_manager.py:236: in test_push_to_device_alternative_method`

**Message**

AssertionError: Calls not found.
Expected: [call('device123', 'C:\\Users\\delan\\AppData\\Local\\Temp\\tmph93vh4ny\\test_binary', '/sdcard/frida-server'),
 call('device123', "su -c 'cp /sdcard/frida-server /data/local/tmp/frida-server && chmod 755 /data/local/tmp/frida-server'"),
 call('device123', 'rm /sdcard/frida-server')]
Actual: [call('device123', "su -c 'cp /sdcard/frida-server /data/local/tmp/frida-server && chmod 755 /data/local/tmp/frida-server'"),
 call('device123', 'rm /sdcard/frida-server')]

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_manager.py:236: in test_push_to_device_alternative_method
    mock_adb_wrapper.shell.assert_has_calls(expected_calls)
C:\Program Files\Python311\Lib\unittest\mock.py:960: in assert_has_calls
    raise AssertionError(
E   AssertionError: Calls not found.
E   Expected: [call('device123', 'C:\\Users\\delan\\AppData\\Local\\Temp\\tmph93vh4ny\\test_binary', '/sdcard/frida-server'),
E    call('device123', "su -c 'cp /sdcard/frida-server /data/local/tmp/frida-server && chmod 755 /data/local/tmp/frida-server'"),
E    call('device123', 'rm /sdcard/frida-server')]
E   Actual: [call('device123', "su -c 'cp /sdcard/frida-server /data/local/tmp/frida-server && chmod 755 /data/local/tmp/frida-server'"),
E    call('device123', 'rm /sdcard/frida-server')]
```
</details>

### 3. test_push_to_device_both_methods_fail
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerDeviceOperations`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_manager.py:254: in test_push_to_device_both_methods_fail`

**Message**

AssertionError: Regex pattern did not match.
 Regex: 'Alternative method failed'
 Input: 'Direct push failed'

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_manager.py:254: in test_push_to_device_both_methods_fail
    await manager._push_to_device("device123", test_path)
src\tower_iq\services\frida_manager.py:125: in _push_to_device
    raise e2
src\tower_iq\services\frida_manager.py:119: in _push_to_device
    await self.adb.push(device_id, str(local_path), temp_path)
C:\Program Files\Python311\Lib\unittest\mock.py:2195: in _execute_mock_call
    raise effect
src\tower_iq\services\frida_manager.py:110: in _push_to_device
    await self.adb.push(device_id, str(local_path), self.DEVICE_PATH)
C:\Program Files\Python311\Lib\unittest\mock.py:2195: in _execute_mock_call
    raise effect
E   src.tower_iq.core.utils.AdbError: Direct push failed

During handling of the above exception, another exception occurred:
tests\services\test_frida_manager.py:253: in test_push_to_device_both_methods_fail
    with pytest.raises(AdbError, match="Alternative method failed"):
E   AssertionError: Regex pattern did not match.
E    Regex: 'Alternative method failed'
E    Input: 'Direct push failed'
```
</details>

### 4. test_stop_server_success
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerServerControl`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_manager.py:324: in test_stop_server_success`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_manager.py:324: in test_stop_server_success
    assert result is True
E   assert False is True
```
</details>

### 5. test_stop_server_multiple_methods
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerServerControl`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_manager.py:358: in test_stop_server_multiple_methods`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_manager.py:358: in test_stop_server_multiple_methods
    assert result is True
E   assert False is True
```
</details>

### 6. test_stop_server_force_kill
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerServerControl`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_manager.py:380: in test_stop_server_force_kill`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_manager.py:380: in test_stop_server_force_kill
    assert result is True
E   assert False is True
```
</details>

### 7. test_wait_for_responsive_with_retries
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerVerification`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_manager.py:531: in test_wait_for_responsive_with_retries`

**Message**

assert 4 == 2

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_manager.py:531: in test_wait_for_responsive_with_retries
    assert call_count == 2  # First failed, second succeeded
    ^^^^^^^^^^^^^^^^^^^^^^
E   assert 4 == 2
```
</details>

### 8. test_provision_success
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerProvisioning`
- **Suite:** `pytest`
- **Trace hint:** `C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:597: in test_provision_success`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:597: in test_provision_success
    assert result is True
E   assert False is True
```
</details>

### 9. test_install_server_success
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerPublicMethods`
- **Suite:** `pytest`
- **Trace hint:** `C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:743: in test_install_server_success`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:743: in test_install_server_success
    assert result is True
E   assert False is True
```
</details>

### 10. test_install_server_failure
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerPublicMethods`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_manager.py:755: in test_install_server_failure`

**Message**

assert True is False

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_manager.py:755: in test_install_server_failure
    assert result is False
E   assert True is False
```
</details>

### 11. test_full_provisioning_workflow
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerIntegration`
- **Suite:** `pytest`
- **Trace hint:** `C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:932: in test_full_provisioning_workflow`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:932: in test_full_provisioning_workflow
    assert result is True
E   assert False is True
```
</details>

### 12. test_install_remove_cycle
- **Class:** `tests.services.test_frida_manager.TestFridaServerManagerIntegration`
- **Suite:** `pytest`
- **Trace hint:** `C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:979: in test_install_remove_cycle`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
C:\Users\delan\Documents\GitHub\TowerIQ\tests\services\test_frida_manager.py:979: in test_install_remove_cycle
    assert install_result is True
E   assert False is True
```
</details>

### 13. test_init_with_all_parameters
- **Class:** `tests.services.test_frida_service.TestFridaServiceInitialization`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:27: in test_init_with_all_parameters`

**Message**

AssertionError: assert <BoundLogger(context={'source': 'FridaService'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> == <BoundLogger(context={'source': 'TestLogger'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])>
 +  where <BoundLogger(context={'source': 'FridaService'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> = <src.tower_iq.services.frida_service.FridaService object at 0x0000020EDA692E90>.logger

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:27: in test_init_with_all_parameters
    assert service.logger == logger
E   AssertionError: assert <BoundLogger(context={'source': 'FridaService'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> == <BoundLogger(context={'source': 'TestLogger'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])>
E    +  where <BoundLogger(context={'source': 'FridaService'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> = <src.tower_iq.services.frida_service.FridaService object at 0x0000020EDA692E90>.logger
```
</details>

### 14. test_script_cache_dir_creation
- **Class:** `tests.services.test_frida_service.TestFridaServiceInitialization`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:57: in test_script_cache_dir_creation`

**Message**

TypeError: unsupported operand type(s) for /: 'Mock' and 'str'

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:57: in test_script_cache_dir_creation
    service = FridaService(config_manager, logger, event_loop)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
src\tower_iq\services\frida_service.py:86: in __init__
    self.script_cache_dir = Path.home() / ".toweriq" / "scripts"
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   TypeError: unsupported operand type(s) for /: 'Mock' and 'str'
```
</details>

### 15. test_attach_handles_exception
- **Class:** `tests.services.test_frida_service.TestFridaServiceAttachment`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:303: in test_attach_handles_exception`

**Message**

assert True is False

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:303: in test_attach_handles_exception
    assert result is False
E   assert True is False
```
</details>

### 16. test_detach_sends_poison_pill
- **Class:** `tests.services.test_frida_service.TestFridaServiceDetachment`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:375: in test_detach_sends_poison_pill`

**Message**

assert 0 == 1
 +  where 0 = <src.tower_iq.services.frida_service.FridaService object at 0x0000020EDA65DF10>.queue_size

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:375: in test_detach_sends_poison_pill
    assert service.queue_size == 1
E   assert 0 == 1
E    +  where 0 = <src.tower_iq.services.frida_service.FridaService object at 0x0000020EDA65DF10>.queue_size
```
</details>

### 17. test_on_message_bulk_payload
- **Class:** `tests.services.test_frida_service.TestFridaServiceMessageProcessing`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:639: in test_on_message_bulk_payload`

**Message**

assert 0 == 2
 +  where 0 = <src.tower_iq.services.frida_service.FridaService object at 0x0000020EDB980090>.queue_size

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:639: in test_on_message_bulk_payload
    assert service.queue_size == 2
E   assert 0 == 2
E    +  where 0 = <src.tower_iq.services.frida_service.FridaService object at 0x0000020EDB980090>.queue_size
```
</details>

### 18. test_check_local_hook_compatibility
- **Class:** `tests.services.test_frida_service.TestFridaServiceHookCompatibility`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:814: in test_check_local_hook_compatibility`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:814: in test_check_local_hook_compatibility
    assert result is True
E   assert False is True
```
</details>

### 19. test_hook_contract_validator_init
- **Class:** `tests.services.test_frida_service.TestHookContractValidator`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:829: in test_hook_contract_validator_init`

**Message**

AssertionError: assert <BoundLogger(context={'source': 'HookContractValidator'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> == <BoundLogger(context={'source': 'TestLogger'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])>
 +  where <BoundLogger(context={'source': 'HookContractValidator'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> = <src.tower_iq.services.frida_service.HookContractValidator object at 0x0000020EDBAB0F50>.logger

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:829: in test_hook_contract_validator_init
    assert validator.logger == logger
E   AssertionError: assert <BoundLogger(context={'source': 'HookContractValidator'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> == <BoundLogger(context={'source': 'TestLogger'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])>
E    +  where <BoundLogger(context={'source': 'HookContractValidator'}, processors=[<function filter_by_level at 0x0000020EA9382020>, <function add_logger_name at 0x0000020EA9382CA0>, <function add_log_level at 0x0000020EA8FF7560>, <structlog.stdlib.PositionalArgumentsFormatter object at 0x0000020EA87A3E90>, <structlog.processors.TimeStamper object at 0x0000020EA8FB4A80>, <structlog.processors.StackInfoRenderer object at 0x0000020EA93850F0>, <structlog.processors.ExceptionRenderer object at 0x0000020EA9013C10>, <structlog.processors.UnicodeDecoder object at 0x0000020EA8FB4C90>, <structlog.processors.JSONRenderer object at 0x0000020EA8FB5390>])> = <src.tower_iq.services.frida_service.HookContractValidator object at 0x0000020EDBAB0F50>.logger
```
</details>

### 20. test_check_local_hook_compatibility
- **Class:** `tests.services.test_frida_service.TestHookContractValidator`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:840: in test_check_local_hook_compatibility`

**Message**

assert False is True

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:840: in test_check_local_hook_compatibility
    assert result is True
E   assert False is True
```
</details>

### 21. test_error_handling_integration
- **Class:** `tests.services.test_frida_service.TestFridaServiceIntegration`
- **Suite:** `pytest`
- **Trace hint:** `tests\services\test_frida_service.py:939: in test_error_handling_integration`

**Message**

assert True is False

<details><summary>Stack / Details</summary>

```
tests\services\test_frida_service.py:939: in test_error_handling_integration
    assert attach_result is False
E   assert True is False
```
</details>

