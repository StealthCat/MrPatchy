#!/usr/bin/env python3
"""Check source/documentation version consistency without importing the application."""
import argparse
import ast
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PINNED_MAJOR=1  # User instruction: change only after an explicit new instruction.


def version(source):
    tree=ast.parse(source)
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='APP_VERSION' for t in node.targets):
            value=ast.literal_eval(node.value)
            if isinstance(value,str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):return value
    # Initial adoption only: read the former literal FastAPI version from the base.
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='FastAPI':
            for keyword in node.keywords:
                if keyword.arg=='version' and isinstance(keyword.value,ast.Constant):return keyword.value.value
    raise ValueError('Missing valid source version')


def check(base_ref=None):
    source=(ROOT/'app/main.py').read_text();current=version(source)
    if current.split('.')[0]!=str(PINNED_MAJOR):raise ValueError(f'Major version must remain {PINNED_MAJOR} until explicitly changed by the user')
    if 'version=APP_VERSION' not in source or "'version':APP_VERSION" not in source:raise ValueError('API metadata must derive from APP_VERSION')
    if f'Current source version: **{current}**' not in (ROOT/'README.md').read_text():raise ValueError('README version differs')
    changelog=(ROOT/'CHANGELOG.md').read_text()
    if re.findall(r'^## ([0-9]+\.[0-9]+\.[0-9]+) — ',changelog,re.M)[0]!=current or not re.search(r'^1\. ',changelog,re.M):raise ValueError('Newest numbered changelog entry differs')
    if base_ref:
        base=subprocess.check_output(['git','show',f'{base_ref}:app/main.py'],cwd=ROOT,text=True)
        if tuple(map(int,current.split('.')))<=tuple(map(int,version(base).split('.'))):raise ValueError('Changed revision must increase source version')
    return current


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--base-ref');args=parser.parse_args()
    try:print('Source version '+check(args.base_ref)+' is consistent')
    except (ValueError,IndexError) as error:parser.exit(1,str(error)+'\n')
