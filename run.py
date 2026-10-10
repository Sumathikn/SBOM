"""
SBOMGuard Application Runner (Workspace root)
Run directly from terminal:
    python3 run.py
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent / "SBOMGuard"
sys.path.insert(0, str(PROJECT_ROOT))
os.environ["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

import uvicorn
from config.settings import HOST, PORT, DEBUG

if __name__ == "__main__":
    uvicorn.run(
        "sbomguard.main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        reload_dirs=[str(PROJECT_ROOT)],
    )
