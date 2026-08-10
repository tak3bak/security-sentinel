# Nomadik Security Sentinel

Local-first threat detection, file integrity monitoring, and security audit orchestration.

## Features
- **File Integrity & Metadata Inspection:** Real-time analysis of system file attributes and permissions.
- **Safe Isolation:** Non-destructive file quarantine mechanism using unique UUID signatures.
- **Local Architecture:** Designed to operate in constrained environments without forcing elevated root privileges.

## Getting Started

### Installation
```bash
./install.sh
```

### Usage
```python
from file_inspector import FileInspector
import quarantine

# Inspect a file
inspector = FileInspector("path/to/target")
metadata = inspector.inspect()
print(metadata)

# Quarantine a suspicious artifact
quarantined_path = quarantine.quarantine_file("path/to/target")
```
