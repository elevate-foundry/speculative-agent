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

### How many models do you need?

**Minimum: 1** (works, but no race). **Recommended minimum: 3** for meaningful speculation.

The agent auto-detects RAM and limits how many models run simultaneously:

```
max_parallel = floor((total_ram - 2 GB) / avg_model_size_gb)
```

Pick a starter set based on your RAM:

| RAM | Pull these models | Parallel at once |
|-----|-------------------|-----------------|
| 8 GB | `llama3.2:1b` + `qwen2.5-coder` | 2 |
| 16 GB | + `gemma3:4b` + `distilled-phi3.5` + `deepseek-r1` | 3 |
| 32 GB | + `mistral` + `llama3.2` | 5+ |
| 64 GB+ | + `llama3.3:70b` | 7+ |

You can pull more models than fit in RAM — extras queue behind the semaphore and run when a slot frees. They just won't truly race in parallel.

**Recommended diversity:** one fast/small model, one code-focused, one deep reasoner.

```bash
# 8 GB minimum
ollama pull llama3.2:1b
ollama pull qwen2.5-coder

# 16 GB recommended
ollama pull llama3.2:1b
ollama pull distilled-phi3.5
ollama pull gemma3:4b
ollama pull qwen2.5-coder
ollama pull deepseek-r1
```

Override which models race (without changing code):
```bash
AGENT_MODELS="llama3.2:1b,qwen2.5-coder:latest" python agent.py
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
