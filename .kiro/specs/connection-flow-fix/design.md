# Design Document

## Overview

This design addresses the critical connection flow and state management issues in TowerIQ by implementing a robust, stateful connection lifecycle management system. The solution focuses on proper resource cleanup, consistent state management, and reliable reconnection capabilities.

The core approach involves:
1. **Centralized State Management**: A single source of truth for connection state with proper synchronization
2. **Lifecycle-Aware Services**: Services that properly manage their internal state through connection lifecycles
3. **Robust Cleanup Mechanisms**: Comprehensive resource cleanup with timeout handling and forced cleanup fallbacks
4. **State Validation and Recovery**: Automatic state consistency checking and recovery mechanisms
5. **Enhanced UI State Synchronization**: Proper UI updates that reflect actual system state

## Architecture

### Connection State Machine

The connection flow will be managed by a formal state machine with the following states:

```
DISCONNECTED -> CONNECTING -> CONNECTED -> ACTIVE -> DISCONNECTING -> DISCONNECTED
     ^                                                      |
     |______________________________________________________|
```

**State Definitions:**
- `DISCONNECTED`: No active connections, all resources cleaned up
- `CONNECTING`: Connection process in progress (multi-stage)
- `CONNECTED`: Device connected, process selected, ready for hook activation
- `ACTIVE`: Hook active and receiving data
- `DISCONNECTING`: Cleanup process in progress

**State Transitions:**
- Each transition has specific entry/exit actions
- Failed transitions automatically trigger cleanup and return to safe state
- State changes are atomic and properly synchronized

### Enhanced Session Manager

The session manager will be upgraded to include:

**Connection State Tracking:**
```python
class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting" 
    CONNECTED = "connected"
    ACTIVE = "active"
    DISCONNECTING = "disconnecting"
    ERROR = "error"

class ConnectionSubState(Enum):
    DEVICE_SELECTION = "device_selection"
    PROCESS_SELECTION = "process_selection"
    HOOK_ACTIVATION = "hook_activation"
    HOOK_ACTIVE = "hook_active"
```

**State Validation:**
- Automatic consistency checking between related state variables
- State transition validation to prevent invalid transitions
- Recovery mechanisms for inconsistent states

**Event Broadcasting:**
- Granular signals for different aspects of state changes
- Batched updates to prevent signal flooding
- Proper signal ordering to maintain consistency

### Service Lifecycle Management

Each service will implement a standardized lifecycle interface:

```python
class ServiceLifecycle:
    async def initialize(self) -> bool
    async def cleanup(self) -> bool
    async def reset(self) -> bool
    def get_state(self) -> ServiceState
    def is_ready_for_connection(self) -> bool
```

**FridaService Enhancements:**
- Proper shutdown state management with reset capabilities
- Message queue lifecycle tied to connection state
- Timeout-based cleanup with forced cleanup fallbacks
- Connection readiness validation

**EmulatorService Enhancements:**
- Device connection state tracking
- Frida server lifecycle management improvements
- Better error recovery for server setup failures

### Connection Stage Manager Improvements

The existing ConnectionStageManager will be enhanced with:

**Robust Error Handling:**
- Detailed error categorization (network, permission, compatibility, etc.)
- User-friendly error messages with actionable suggestions
- Automatic retry logic with exponential backoff
- Graceful degradation for partial failures

**State Persistence:**
- Stage progress persistence across UI updates
- Recovery from interrupted connection processes
- Proper cleanup of partial connection states

**Progress Reporting:**
- Real-time progress updates with percentage completion
- Detailed status messages for each stage
- Time estimates for long-running operations

## Components and Interfaces

### ConnectionFlowController

A new centralized controller for managing the entire connection flow:

```python
class ConnectionFlowController:
    def __init__(self, session_manager, services, ui_manager)
    
    # Main flow control
    async def start_connection_flow(self, device_id: str, process_info: dict) -> bool
    async def disconnect_flow(self, cleanup_level: CleanupLevel) -> bool
    async def reconnect_flow(self) -> bool
    
    # State management
    def get_connection_state(self) -> ConnectionState
    def validate_state_consistency(self) -> List[StateInconsistency]
    async def recover_from_inconsistent_state(self) -> bool
    
    # Resource management
    async def cleanup_all_resources(self, timeout: float = 5.0) -> bool
    async def prepare_for_new_connection(self) -> bool
```

**Responsibilities:**
- Orchestrate the entire connection lifecycle
- Ensure proper state transitions and validation
- Coordinate between services and UI components
- Handle error recovery and resource cleanup

### Enhanced UI State Manager

A new component to manage UI state synchronization:

```python
class UIStateManager:
    def __init__(self, session_manager, connection_controller)
    
    # UI synchronization
    def sync_ui_with_connection_state(self, state: ConnectionState)
    def update_connection_progress(self, stage: str, progress: int, message: str)
    def handle_connection_error(self, error: ConnectionError)
    
    # Navigation management
    def navigate_to_appropriate_stage(self, force_stage: Optional[int] = None)
    def update_breadcrumbs(self, current_stage: int)
    def validate_ui_state_consistency(self) -> bool
```

### Resource Cleanup Manager

A dedicated component for managing resource cleanup:

```python
class ResourceCleanupManager:
    def __init__(self, services: List[ServiceLifecycle])
    
    # Cleanup operations
    async def cleanup_all_services(self, timeout: float = 5.0) -> CleanupResult
    async def cleanup_service(self, service: ServiceLifecycle, timeout: float = 2.0) -> bool
    async def force_cleanup_all(self) -> None
    
    # Validation
    def validate_cleanup_completion(self) -> List[CleanupIssue]
    async def verify_services_ready(self) -> bool
```

## Data Models

### Connection State Model

```python
@dataclass
class ConnectionStateSnapshot:
    main_state: ConnectionState
    sub_state: Optional[ConnectionSubState]
    device_id: Optional[str]
    process_info: Optional[Dict]
    error_info: Optional[ErrorInfo]
    stage_progress: Dict[str, StageProgress]
    timestamp: datetime
    
    def is_consistent(self) -> bool
    def get_inconsistencies(self) -> List[StateInconsistency]
```

### Error Information Model

```python
@dataclass
class ErrorInfo:
    error_type: ErrorType
    error_code: str
    user_message: str
    technical_details: str
    recovery_suggestions: List[str]
    is_recoverable: bool
    retry_count: int
    timestamp: datetime
```

### Stage Progress Model

```python
@dataclass
class StageProgress:
    stage_name: str
    status: StageStatus
    progress_percent: int
    message: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    error_info: Optional[ErrorInfo]
    retry_count: int
```

## Error Handling

### Error Categories

**Network Errors:**
- ADB connection failures
- Frida server download failures
- Device communication timeouts

**Permission Errors:**
- Root access denied
- Process attachment denied
- File system permission issues

**Compatibility Errors:**
- Unsupported device architecture
- Incompatible app versions
- Missing system components

**Resource Errors:**
- Insufficient device storage
- Memory allocation failures
- Port conflicts

### Error Recovery Strategies

**Automatic Recovery:**
- Retry with exponential backoff for transient errors
- Alternative approaches for known issues (e.g., different frida server start methods)
- Automatic state reset for recoverable errors

**User-Guided Recovery:**
- Clear error messages with specific actions
- Step-by-step troubleshooting guides
- Option to skip problematic stages when possible

**Graceful Degradation:**
- Partial functionality when full connection fails
- Safe mode operation with limited features
- Proper cleanup when recovery is impossible

## Testing Strategy

### Unit Testing

**State Management Tests:**
- State transition validation
- Consistency checking algorithms
- Error recovery mechanisms
- Resource cleanup verification

**Service Lifecycle Tests:**
- Service initialization and cleanup
- Error handling in each service
- Resource leak detection
- Timeout handling

### Integration Testing

**Connection Flow Tests:**
- End-to-end connection scenarios
- Disconnect/reconnect cycles
- Error injection and recovery
- UI state synchronization

**Cross-Component Tests:**
- Service coordination
- State synchronization between components
- Event propagation and handling
- Resource sharing and cleanup

### User Acceptance Testing

**Reliability Tests:**
- Multiple connection/disconnection cycles
- Connection under various error conditions
- Recovery from unexpected failures
- Long-running connection stability

**Usability Tests:**
- Clear error messages and recovery guidance
- Intuitive navigation between stages
- Appropriate progress feedback
- Responsive UI during operations

### Performance Testing

**Resource Usage Tests:**
- Memory leak detection during connection cycles
- CPU usage during connection processes
- Network resource utilization
- Cleanup operation performance

**Scalability Tests:**
- Multiple device connections
- Large process lists
- Extended operation periods
- Resource cleanup under load

## Implementation Phases

### Phase 1: Core State Management
- Implement enhanced SessionManager with state machine
- Add ConnectionFlowController with basic lifecycle management
- Implement ResourceCleanupManager
- Add comprehensive logging and debugging

### Phase 2: Service Enhancements
- Upgrade FridaService with proper lifecycle management
- Enhance EmulatorService with better state tracking
- Improve ConnectionStageManager error handling
- Add service readiness validation

### Phase 3: UI Integration
- Implement UIStateManager
- Update connection panel with enhanced progress display
- Improve navigation and breadcrumb management
- Add error display and recovery UI

### Phase 4: Testing and Validation
- Comprehensive testing of all connection scenarios
- Performance and reliability testing
- User acceptance testing
- Documentation and troubleshooting guides

Each phase will be thoroughly tested before proceeding to the next, ensuring that the foundation is solid before building additional functionality.