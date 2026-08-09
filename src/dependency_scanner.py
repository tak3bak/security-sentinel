import os


class DependencyScanner:
    def __init__(self, requirements_path="requirements.txt"):
        self.requirements_path = requirements_path
        # Example database of vulnerable versions
        self.vulnerable_deps = {"requests": "2.25.1", "flask": "1.1.2"}

    def scan(self):
        issues = []
        if not os.path.exists(self.requirements_path):
            return issues

        with open(self.requirements_path, "r") as f:
            for line in f:
                for dep, ver in self.vulnerable_deps.items():
                    if dep in line and ver in line:
                        issues.append(f"Vulnerable dependency: {dep} version {ver}")
        return issues
