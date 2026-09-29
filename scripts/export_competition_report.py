import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.report import export_report
if __name__ == '__main__':
    a,b=export_report(); print(a); print(b)
