# Machine Control Agent — Parallel Speculative CoT

All locally pulled Ollama models race in parallel using chain-of-thought reasoning.
A supervisor monitors token streams in real-time and short-circuits the race when
any model reaches high confidence. **Every proposed action requires your explicit
approval before it runs.**

## Setup

```bash
pip install -r requirements.txt
```

Make sure Ollama is running:
```bash
ollama serve
```

Pull at least one model:
```bash
ollama pull llama3.2
ollama pull qwen2.5-coder
```

## Run

```bash
# Interactive REPL
python agent.py

# Single task
python agent.py "list all Python files in my home directory"

# List models + exit
python agent.py --list-models
```

## How it works

1. **Discover** — auto-detects all locally pulled Ollama models
2. **Warmup** — sends a `ping` to each model in parallel; failed models are excluded
3. **Hardware limit** — `max_parallel_models` is derived from CPU cores, RAM, and GPU VRAM so you don't thrash the machine
4. **Race** — all models stream their reasoning simultaneously
5. **Supervise** — the supervisor scores each stream every 150ms; if any model hits `≥85%` confidence AND has a valid action block, it wins and the others are cancelled
6. **Approve** — you see the proposed action and must type `y` to run it
7. **Execute** — runs via `bash`, `python_exec` (subprocess sandbox), `pyautogui`, or `write_file`

## Action types

| Type | What it does |
|------|-------------|
| `bash` | Runs a shell command via `subprocess` |
| `python_exec` | Writes code to a temp file and runs it in a subprocess |
| `pyautogui` | Controls mouse/keyboard (`click`, `type`, `hotkey`, `screenshot`, `scroll`, `moveTo`) |
| `write_file` | Writes content to a file path |
| `read_file` | Reads a file and returns its content |
| `noop` | Does nothing (task complete) |

## Safety

- `FAILSAFE = True` on pyautogui: move mouse to top-left corner to instantly abort
- All destructive actions always require `y` approval
- Models run in a separate HTTP session; no persistent state between races
- Python code runs in a child subprocess, not `exec()` in-process

## Tuning

Edit `supervisor.py`:
- `SHORT_CIRCUIT_THRESHOLD` (default `0.85`) — lower = faster short-circuit, less accurate
- `MIN_TOKENS_FOR_SHORTCIRCUIT` (default `40`) — minimum reasoning tokens before a win is possible

Edit `config.py`:
- `OLLAMA_BASE` — point at a remote Ollama instance if needed
