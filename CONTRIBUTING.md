# Contributing

CloudLeak Sentinel is a defensive security project. Contributions should preserve the following rules:

1. Use only synthetic, public, or explicitly authorized test data.
2. Never commit real credentials, API tokens, private keys, passwords, or private datasets.
3. Do not add credential validation, account access, exploitation, or unauthorized crawling features.
4. Add or update automated tests for detector/source changes.
5. Keep synthetic benchmark claims clearly separated from real-world evaluation claims.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```
