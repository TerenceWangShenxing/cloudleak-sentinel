import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sentinel.experiments import run_final_experiments
import json
print(json.dumps(run_final_experiments(),ensure_ascii=False,indent=2))
