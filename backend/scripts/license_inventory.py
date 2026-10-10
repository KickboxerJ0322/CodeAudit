"""Write metadata inventory. No credentials, network access or package source code."""
import json
from importlib.metadata import distributions
from pathlib import Path

root = Path(__file__).resolve().parents[2]
required = {line.split('==')[0].lower().replace('_', '-') for line in (root / 'backend/requirements.lock').read_text().splitlines() if '==' in line}
python = []
for dist in distributions():
    name = dist.metadata.get('Name', '')
    if name.lower().replace('_', '-') not in required:
        continue
    value = dist.metadata.get('License-Expression') or dist.metadata.get('License') or 'UNKNOWN'
    python.append({'name': name, 'version': dist.version, 'license': value.splitlines()[0] if value else 'UNKNOWN'})
lock = json.loads((root / 'frontend/package-lock.json').read_text(encoding='utf-8'))
javascript = [{'name': path.removeprefix('node_modules/'), 'version': package.get('version'), 'license': package.get('license', 'UNKNOWN'), 'dev': package.get('dev', False)} for path, package in lock['packages'].items() if path]
output = root / 'docs/dependency-inventory.json'
output.write_text(json.dumps({'note': 'Metadata inventory only; preserve actual notices separately before redistributing binaries.', 'python': sorted(python, key=lambda x: x['name']), 'javascript': javascript}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Inventory: Python {len(python)}, JavaScript {len(javascript)}')
