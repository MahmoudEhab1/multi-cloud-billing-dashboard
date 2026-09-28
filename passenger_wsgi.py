import os
import sys
from pathlib import Path

APP_ROOT = Path(os.environ.get("APP_ROOT", Path(__file__).resolve().parent))
sys.path.insert(0, str(APP_ROOT))
os.chdir(APP_ROOT)

from app import application
