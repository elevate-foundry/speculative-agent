# Architecture Explanation

## Core Design Principles

### 1. Modularity
The system is built with clear separation of concerns:
- **File Management**: Handles all file operations (create, read, write, delete)
- **Process Control**: Manages subprocess execution and monitoring
- **User Interface**: Coordinates with UI automation (pyautogui/playwright)
- **Command Routing**: Directs tasks to appropriate subsystems

### 2. Layered Architecture
```
┌─────────────────────────┐
│        User Task        │
├─────────────────────────┤
│      Command Router     │
├─────────────────────────┤
│   Subsystem Coordinator │
├─────────────────────────┤
│  File / Process / UI    │
│      Modules            │
└─────────────────────────┘
```

### 3. Execution Flow
1. **Task Reception**: Parse user requirements
2. **Command Mapping**: Translate to specific operations
3. **Subsystem Dispatch**: Route to appropriate module
4. **Execution**: Perform the operation with error handling
5. **Verification**: Confirm completion and report status

### 4. Key Features
- **Atomic Operations**: Each action is self-contained and verifiable
- **Error Recovery**: Built-in retry mechanisms and fallback strategies
- **State Tracking**: Maintains context across operations
- **Resource Management**: Efficient handling of file descriptors and processes

### 5. Integration Points
- **File System**: Direct POSIX operations with path validation
- **Process Management**: subprocess with timeout and signal handling
- **UI Automation**: Context-aware switching between pyautogui and playwright
- **Screen Coordinates**: Pixel-perfect operations based on 1920x1080 reference