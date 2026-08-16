#!/usr/bin/env python3
import os, sys, uvicorn
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_sentinel.main_app import app

def main():
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main()
