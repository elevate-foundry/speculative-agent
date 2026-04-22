# Architecture Explanation

## Core Design Principles

This system is built around a modular, extensible agent architecture that separates concerns into distinct, testable components.

### Key Components

1. **Action Dispatcher**: Routes incoming requests to the appropriate handler based on action type
2. **File System Module**: Handles all file operations with proper error handling and permissions management
3. **Screen Management**: Manages display contexts, screenshots, and coordinate-based interactions
4. **Execution Engine**: Runs code in isolated environments with timeout controls
5. **Browser Automation**: Provides Playwright-based web interaction capabilities
6. **GUI Automation**: Offers pyautogui functions for native desktop control

### Interaction Patterns

- **Declarative Configuration**: Actions are specified as structured JSON with clear payload schemas
- **Context Preservation**: Screen dimensions and coordinate systems are maintained across operations
- **Safety Boundaries**: File operations are constrained to designated working directories
- **Extensibility Hooks**: New action types can be added without modifying core dispatch logic

### Workflow Architecture

1. Request → Validation → Action Selection → Execution → Response
2. Each step includes error handling and logging
3. Screen context is preserved across related operations
4. Resource cleanup is guaranteed through structured execution

### Security Considerations

- File system access is path-validated
- Execution timeouts prevent resource exhaustion
- Browser automation runs in controlled contexts
- No arbitrary network access without explicit configuration