# Security Sentinel

## Overview
Security Sentinel is an automated security monitoring tool designed to detect and respond to sensitive information leaks in files. It monitors specified directories for changes, inspects files for sensitive data, and triggers appropriate responses, such as quarantining files or enriching detected IP addresses with OSINT data.

## Features
- Monitors directories for file changes.
- Inspects files for sensitive information (e.g., AWS keys, passwords).
- Quarantines files containing sensitive data.
- Extracts and enriches IP addresses found in files using the Spiderfoot API.
- Configurable through environment variables and a YAML configuration file.

## Project Structure
```
security-sentinel
├── src
│   ├── security_sentinel
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── file_inspector.py
│   │   ├── quarantine.py
│   │   ├── spiderfoot.py
│   │   ├── watcher.py
│   │   └── main.py
│   └── scripts
│       └── run_sentinel.py
├── tests
│   ├── test_file_inspector.py
│   ├── test_quarantine.py
│   ├── test_spiderfoot.py
│   └── test_watcher.py
├── .gitignore
├── README.md
├── requirements.txt
├── pyproject.toml
└── config
    └── config.example.yaml
```

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/security-sentinel.git
   cd security-sentinel
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
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