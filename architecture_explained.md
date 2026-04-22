# Architecture Explanation

## System Overview
This agent operates as a machine control agent running on macOS, designed to execute user-specified tasks through structured actions.

## Core Components

### 1. Action Execution Engine
- Receives user tasks and translates them into structured actions
- Supports multiple action types: bash, python_exec, pyautogui, playwright, write_file, read_file
- Each action includes confidence scoring and detailed payload specifications

### 2. Action Types
- **bash**: Execute shell commands with configurable timeouts
- **python_exec**: Run Python code snippets with execution time limits
- **pyautogui**: Control native macOS GUI applications (screenshot, click, type, etc.)
- **playwright**: Web automation framework for browser-based tasks
- **write_file**: Create and write to files with specified modes
- **read_file**: Read file contents
- **noop**: No operation for task completion confirmation

### 3. Screen Context Management
- Maintains screen capture at 1920x1080px resolution
- Screenshots stored in temporary directories for coordinate reference
- Pixel-perfect positioning for GUI interactions

### 4. File System Operations
- All file operations use absolute paths for reliability
- Supports both creation and reading of files
- Configurable write modes (write, append, etc.)

## Execution Flow
1. User provides task description
2. Agent reasons through available action types
3. Selects optimal action with confidence scoring
4. Executes action with proper error handling
5. Returns structured results

## Safety Features
- Confidence scoring for all actions (0.0-1.0)
- Timeout configurations for long-running operations
- Structured payload validation before execution
- Screen coordinate validation for GUI operations