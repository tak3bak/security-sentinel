import sys
# Logic to call your firewall/API to revoke access
# Example: os.system("ufw deny from " + sys.argv[1])
print(f"Mitigating access for: {sys.argv[1]}")
