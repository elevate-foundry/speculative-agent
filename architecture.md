# Agent Architecture

## Overview
This is a macOS machine control agent that operates through structured actions. It can interact with the file system, execute code, control the GUI, and automate web browsers.

## Core Components

### 1. Action Execution Engine
- Receives structured action requests
- Validates parameters and confidence levels
- Executes the appropriate handler for each action type

### 2. Action Types
- **bash**: Execute shell commands with timeout control
- **python_exec**: Run Python code in the execution environment
- **pyautogui**: Control native macOS GUI applications (keyboard/mouse)
- **playwright**: Automate web browsers (Chromium-based)
- **write_file**: Create and write files to the filesystem
- **read_file**: Read file contents
- **noop**: No-operation action for idle states

### 3. Coordinate System
- Screen resolution: 1920x1080px
- All GUI actions use pixel coordinates based on this reference
- Screenshots are saved to temporary directories for reference

### 4. Safety Mechanisms
- Confidence scoring (0.0-1.0) for all actions
- Timeout controls on long-running operations
- Structured parameter validation

## File Locations
- Architecture documentation: `/Users/ryanbarrett/agent/architecture.md`
- Screen captures: `/var/folders/.../agent_screen.png`
- Temporary files: `/var/folders/.../`