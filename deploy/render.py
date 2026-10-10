"""Render configuration files only. Does not contact Google Cloud or deploy."""
import argparse
import re
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--project', default='jumpeicloud')
parser.add_argument('--region', default='asia-northeast1')
parser.add_argument('--sha', required=True)
parser.add_argument('--output', default='artifacts/deploy')
args = parser.parse_args()
if not re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]', args.project) or not re.fullmatch(r'[a-z]+-[a-z]+[0-9]', args.region) or not re.fullmatch(r'[a-f0-9]{40}', args.sha):
    parser.error('project/region/sha invalid')
output = Path(args.output)
output.mkdir(parents=True, exist_ok=True)
for name in ['service.yaml', 'job.yaml']:
    text = (Path(__file__).parent / name).read_text(encoding='utf-8')
    text = text.replace('jumpeicloud', args.project).replace('asia-northeast1', args.region).replace('REPLACE_COMMIT_SHA', args.sha)
    (output / name).write_text(text, encoding='utf-8')
print('Rendered only; not deployed.')
