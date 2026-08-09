import json
import os

FILE_PATH = os.path.expanduser(
    "~/security-sentinel/compliance/Cross_Framework_Mapping/unified_mapping.jsonl"
)


def load_mapping(file_path):
    mappings = []
    metadata = None
    try:
        with open(file_path, "r") as f:
            for line in f:
                stripped_line = line.strip()
                if not stripped_line:
                    continue  # Skip empty lines
                entry = json.loads(stripped_line)
                if entry.get("type") == "metadata":
                    metadata = entry
                else:
                    mappings.append(entry)
        return metadata, mappings
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None, []


def display_report(file_path):
    metadata, controls = load_mapping(file_path)
    if metadata:
        print(f"--- Framework Mapping: {metadata['control_name']} ---")
        print(f"Overlap Strength: {metadata['overlap_strength'].upper()}")
        print("-" * 50)
    if controls:
        print(f"{'ID':<10} | {'Description':<35} | {'Priority'}")
        print("-" * 60)
        for c in controls:
            print(
                f"{c.get('control_id', 'N/A'):<10} | {c.get('description', 'N/A'):<35} | {c.get('priority', 'N/A')}"
            )


if __name__ == "__main__":
    display_report(FILE_PATH)
