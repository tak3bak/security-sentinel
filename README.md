<<<<<<< HEAD
# Security Sentinel 🛡️

**Security Sentinel** is an automated, real-time security monitoring tool designed to detect, contain, and analyze sensitive information leaks across monitored file systems. It continuously watches designated directories for file creation or modification, scans content for high-risk secrets (such as API keys, credentials, and tokens), automatically quarantines policy-violating files, and enriches exposed IP addresses with threat intelligence via the SpiderFoot API.

---

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## Key Features

- ⏱️ **Real-Time Directory Monitoring**: Tracks file creation and modification events asynchronously using event-driven file watchers.
- 🔍 **Deep Inspection & Secret Detection**: Uses robust regex signatures and entropy analysis to identify AWS keys, API tokens, passwords, private keys, and credentials.
- 📦 **Automated Isolation & Quarantine**: Instantly removes flagged files from sensitive paths and moves them to a secure quarantine workspace with strict file permissions.
- 🌐 **OSINT & Threat Intelligence**: Extracts embedded IP addresses from flagged files and enriches them with OSINT data through the SpiderFoot API.
- ⚙️ **Flexible Configuration**: Fully customizable behavior controlled via YAML configuration files and standard environment variable overrides.
- 📊 **Structured Audit Logging**: Generates detailed, structured logs for security information and event management (SIEM) integration.

---

## Project Structure

```text
security-sentinel/
├── src/
│   ├── security_sentinel/
│   │   ├── __init__.py          # Package initialization
│   │   ├── config.py             # Configuration parsing & validation
│   │   ├── file_inspector.py     # Regex pattern matching & secret detection
│   │   ├── quarantine.py         # Quarantine file handling & security policies
│   │   ├── spiderfoot.py         # SpiderFoot API wrapper for OSINT enrichment
│   │   ├── watcher.py            # File system event listener (Watchdog integration)
│   │   └── main.py               # Core orchestrator and execution flow
│   └── scripts/
│       └── run_sentinel.py       # Main CLI entrypoint script
├── tests/
│   ├── test_file_inspector.py   # Unit tests for secret detection logic
│   ├── test_quarantine.py       # Unit tests for quarantine operations
│   ├── test_spiderfoot.py       # Mocks and tests for SpiderFoot API integrations
│   └── test_watcher.py          # Functional tests for file system watchers
├── config/
│   └── config.example.yaml      # Configuration template file
├── .gitignore
├── pyproject.toml               # Build system configuration & metadata
├── README.md                    # Project documentation
└── requirements.txt             # Python dependency specifications
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Configure the application by copying the example configuration file:
   ```
   cp config/config.example.yaml config/config.yaml
   ```

5. Edit `config/config.yaml` to set your desired configuration options.

## Usage
To start the Security Sentinel application, run the following command:
```
python src/scripts/run_sentinel.py
```

## Testing
To run the tests, ensure you have installed the dependencies and then execute:
```
pytest tests/
```

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes. Ensure that your code adheres to the project's coding standards and includes appropriate tests.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
=======
# Nomadik Security Sentinel

Production-grade automated security monitoring and active-defense platform tailored for SMBs.

## Features
- **Automated Incident Response:** Real-time log monitoring and active defense orchestration.
- **Compliance Tracking:** Automated auditing for industry frameworks and compliance policies.
- **Microservice Ready:** Containerized execution with Docker and lightweight FastAPI engine.

## Quickstart
```bash
cp config/.env.example config/.env
docker-compose up -d --build
```
>>>>>>> 360eff33 (refactor: consolidate configs, standardize layout, add docs and workflows)
