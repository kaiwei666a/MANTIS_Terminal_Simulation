# MANTIS Terminal Simulation

MANTIS provides an Ubuntu-style interactive terminal over SSH for terminal behavior simulation and honeypot session recording. It combines local command rules, a ModernBERT classifier, and remote LLM calls to maintain a simulated system snapshot, with SCP/SFTP support for file transfers.

## Project Architecture

```text
MANTIS_Terminal_Simulation/
├── main.py    # Entry point: directories, logging, SSH keys, service lifecycle
├── terminal_config.py        # Listening address, port, model path, and runtime settings
├── server/                   # SSH authentication, connections, and request dispatch
├── runtime/                  # Interactive shell, one-shot exec, and command orchestration
├── agents/
│   ├── strategic_agent.py    # Local command classification and history context management
│   ├── arbiter_agent.py      # Local state operations, mutation planning, validation, and application
│   ├── response_agent.py     # Terminal responses and top frame generation
│   └── history_pruning.py    # History selection by state changes, repetition, and age
├── tools/                    # Ubuntu command simulation, deterministic plans, and model tool interfaces
├── system_state/             # Default snapshots, virtual filesystem, and state JSON persistence
├── storage/                  # Session records, authentication audits, and application logging
├── transfer/                 # SCP/SFTP, Docker downloads, and upload processing
├── model/                    # Local classifier model
├── data/archive/             # Historical session datasets
├── records/                  # Runtime data; missing runtime subdirectories are created automatically
│   ├── logs/                 # Application logs, authentication logs, and upload audits
│   ├── state/                # System snapshots and command session records
│   ├── keys/                 # Automatically generated SSH host keys
│   └── uploads/              # Received files and the quarantine directory
├── environment.yml           # Conda environment and Python dependencies
├── docker-compose.yml        # Optional SFTP and download container
└── Dockerfile.sftp
```



### Execution Flow

```text
main.py
    → SSH Server accepts connections
        ├── shell / exec → classify and process commands → return output and record sessions
        └── SCP / SFTP  → transfer files and process uploads
```



## Quick Start

Run the following commands from the project root. You need Conda and an SSH client. Docker is optional and is needed for container file copying or real network downloads.

### 1. Install Python Dependencies

Use these commands on Windows PowerShell or Linux:

```bash
conda env create -f environment.yml
conda activate mantis-sim
```



### 2. Check the Local Model

Keep the classifier weights, configuration, and tokenizer files in:

```text
model/modernbert_par_2_jaur_1/
├── config.json
├── model.safetensors
├── tokenizer.json
├── tokenizer_config.json
└── special_tokens_map.json
```

The classifier loads on first use, using CUDA when available and CPU otherwise. Loading or inference failures are logged and fall back to `read` classification. A running SSH listener does not confirm that the classifier has loaded successfully.

### 3. Set the API Key and Start the Simulator

Windows PowerShell:

```powershell
$env:OPENAI_API_KEY = "your_openai_api_key"
python main.py
```

Linux:

```bash
export OPENAI_API_KEY="your_openai_api_key"
python main.py
```

The default listener is `0.0.0.0:2222`. The following log message confirms that the SSH listener has started:

```text
[*] Fake SSH server listening on 0.0.0.0:2222
```

SSH host keys are generated automatically in `records/keys/`. Application logs are written to `records/logs/honeypot.log`.

### 4. Connect to the Simulated Terminal

Leave the server running and open another terminal:

```bash
ssh -p 2222 root@127.0.0.1
```

Confirm the host key when prompted on the first connection. The current honeypot implementation accepts any password and records authentication details. The `sudo` password inside the simulated terminal is configured separately.

To execute a single command:

```bash
ssh -p 2222 root@127.0.0.1 "ls -l"
```

For a remote deployment, replace `127.0.0.1` with the server address. 

## Optional: Docker File Transfer Backend

To copy uploaded files into the container or perform real downloads through commands connected to the container download callbacks, run:

```bash
docker compose up -d --build
```

The `terminal_sftp` container provides SFTP storage and the `wget`, `curl`, and `git` download tools. Start the Python simulator separately using the steps above.


| Port | Purpose                                        |
| ---- | ---------------------------------------------- |
| 2222 | Python simulator's SSH and SCP/SFTP interfaces |
| 8022 | Docker container's SFTP interface              |


Uploads are first saved under `records/uploads/`, then scanned, copied, audited, and registered in the system state according to the backend configuration. Terminal simulation can run without Docker, but container copying and real downloads will be unavailable; some download branches fall back to simulated results.

## Model

- [Routing Model](https://huggingface.co/kaiwei123/modernbert_par_2_jaur_1)



## Dataset

- [Routing Dataset](https://huggingface.co/datasets/kaiwei123/routing-dataset)
- [Response Dataset](https://huggingface.co/datasets/kaiwei123/response_data_snapshot)



## References

```bibtex
@inproceedings{wei-wang-2025-agentic,
  title     = {Poster: Agentic Shell Honeypot Using Structured Logging},
  author    = {Wei, Kai and Wang, Guangjing},
  booktitle = {Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security},
  year      = {2025},
  pages     = {4803--4805},
  publisher = {ACM},
  doi       = {10.1145/3719027.3760731},
  url       = {https://doi.org/10.1145/3719027.3760731}
}

@inproceedings{wei-etal-2026-multi,
  title     = {A Multi-Agent Framework for High-Interaction Terminal Simulation},
  author    = {Wei, Kai and Cui, Yuwen and Shen, Kehan and Wei, Hua and Wang, Guangjing},
  editor    = {Liakata, Maria and Moreira, Viviane P. and Zhang, Jiajun and Jurgens, David},
  booktitle = {Proceedings of the 64th Annual Meeting of the Association for Computational Linguistics (Volume 1: Long Papers)},
  month     = jul,
  year      = {2026},
  address   = {San Diego, California, United States},
  publisher = {Association for Computational Linguistics},
  pages     = {32828--32845},
  doi       = {10.18653/v1/2026.acl-long.1515},
  url       = {https://aclanthology.org/2026.acl-long.1515/},
  isbn      = {979-8-89176-390-6}
}
```



## Future Update

The future updates will be available at [RaiseAILab/Honeypot](https://github.com/RaiseAILab/Honeypot)