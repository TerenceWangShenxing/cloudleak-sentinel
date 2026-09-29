#!/usr/bin/env python3
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.benchmark import run_benchmark
print(json.dumps(run_benchmark(), ensure_ascii=False, indent=2))
