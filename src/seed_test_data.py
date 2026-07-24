import os

def seed():
    print("[+] Seeding mock environment telemetry data...")
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Seed Leaks Folder
    target_dir = os.path.join(base_path, "data")
    os.makedirs(target_dir, exist_ok=True)
    
    mock_leak_file = os.path.join(target_dir, "mock_secrets.txt")
    with open(mock_leak_file, "w") as f:
        f.write("sk_live_1234567890abcdefGHJKLM\n")
        f.write("ghp_1234567890abcdefghijklmnopqrstuvWXYZ\n")
    print(f"[+] Created mock vulnerability leak target: {mock_leak_file}")

    # 2. Seed Mock System Auth Logs
    mock_log_path = os.path.join(base_path, "data", "mock_auth.log")
    with open(mock_log_path, "w") as f:
        # 4 fake failed attacks from a rogue IP to cross our threshold of 3
        f.write("Jun 30 10:00:01 server sshd[1234]: Failed password for root from 198.51.100.42 port 49152 ssh2\n")
        f.write("Jun 30 10:01:02 server sshd[1234]: Failed password for root from 198.51.100.42 port 49153 ssh2\n")
        f.write("Jun 30 10:02:03 server sshd[1234]: Failed password for invalid user admin from 198.51.100.42 port 49154 ssh2\n")
        f.write("Jun 30 10:03:04 server sshd[1234]: Failed password for root from 198.51.100.42 port 49155 ssh2\n")
    print(f"[+] Injected malicious trace log entries into: {mock_log_path}")

if __name__ == "__main__":
    seed()