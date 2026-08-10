import math
import re
from typing import Dict, List, Any


class SecretDetector:
    """Detects credentials, tokens, and high-entropy secrets in text and source code."""

    PATTERNS: Dict[str, str] = {
        'JWT Token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'AWS Access Key ID': r'(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}',
        'AWS Secret Access Key': r'(?i)aws_?secret_?access_?key\s*[:=]\s*["'']?([A-Za-z0-9/+=]{40})["'']?',
        'Slack Token': r'xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
        'Private Key Header': r'-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----',
        'Generic Bearer Token': r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}',
        'Generic Assignment (API Key/Secret)': r'(?i)(api[_-]?key|secret|token|password|auth_token)\s*[:=]\s*["'']([A-Za-z0-9_\-]{16,})["'']'
    }

    def __init__(self, entropy_threshold: float = 4.5, min_secret_length: int = 16):
        self.entropy_threshold = entropy_threshold
        self.min_secret_length = min_secret_length
        self._compiled_patterns = {
            name: re.compile(pattern) for name, pattern in self.PATTERNS.items()
        }

    @staticmethod
    def calculate_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        lines = text.splitlines()
        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or len(line_str) < self.min_secret_length:
                continue
            for rule_name, compiled_regex in self._compiled_patterns.items():
                for match in compiled_regex.finditer(line_str):
                    match_val = match.group(0)
                    findings.append({
                        'line': line_num,
                        'type': rule_name,
                        'match': self._redact_secret(match_val),
                        'entropy': self.calculate_entropy(match_val),
                        'detection_method': 'regex_pattern'
                    })
            tokens = re.findall(r'[A-Za-z0-9_+/=-]{' + str(self.min_secret_length) + r',}', line_str)
            for token in tokens:
                entropy = self.calculate_entropy(token)
                if entropy >= self.entropy_threshold:
                    if not any(f['line'] == line_num and f['match'] == self._redact_secret(token) for f in findings):
                        findings.append({
                            'line': line_num,
                            'type': 'High Entropy String',
                            'match': self._redact_secret(token),
                            'entropy': entropy,
                            'detection_method': 'shannon_entropy'
                        })
        return findings

    @staticmethod
    def _redact_secret(secret: str) -> str:
        if len(secret) <= 8:
            return '******'
        return f'{secret[:4]}...{secret[-4:]}'
