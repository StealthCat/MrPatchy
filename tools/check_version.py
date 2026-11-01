#!/usr/bin/env python3
"""Validate development metadata or a coordinator-prepared integration."""
import argparse
import ast
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PINNED_MAJOR=1  # User instruction: change only after an explicit new instruction.


def version(source, *, allow_legacy=False):
    tree=ast.parse(source)
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='APP_VERSION' for t in node.targets):
            try:value=ast.literal_eval(node.value)
            except (ValueError,TypeError):raise ValueError('Missing valid source version') from None
            if isinstance(value,str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):return value
            raise ValueError('Missing valid source version')
    # Initial adoption only: read the former literal FastAPI version from the base.
    if allow_legacy:
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='FastAPI':
                for keyword in node.keywords:
                    if keyword.arg=='version' and isinstance(keyword.value,ast.Constant):
                        value=keyword.value.value
                        if isinstance(value,str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):return value
    raise ValueError('Missing valid source version')


def changelog_sections(text):
    return list(re.finditer(r'^## ([0-9]+\.[0-9]+\.[0-9]+) — .+$',text,re.M))


def check(base_ref=None, *, allow_unversioned=False, pr_number=None):
    if allow_unversioned and not base_ref:raise ValueError('Development validation requires a base ref')
    if pr_number is not None and (allow_unversioned or not base_ref or pr_number<1):raise ValueError('PR validation requires strict integration mode and a base ref')
    source=(ROOT/'app/main.py').read_text();current=version(source)
    if current.split('.')[0]!=str(PINNED_MAJOR):raise ValueError(f'Major version must remain {PINNED_MAJOR} until explicitly changed by the user')
    if 'version=APP_VERSION' not in source or "'version':APP_VERSION" not in source:raise ValueError('API metadata must derive from APP_VERSION')
    changelog=(ROOT/'CHANGELOG.md').read_text()
    sections=changelog_sections(changelog)
    if not sections or sections[0].group(1)!=current:raise ValueError('Newest versioned changelog entry differs')
    entry=changelog[sections[0].end():sections[1].start() if len(sections)>1 else len(changelog)]
    if not re.search(r'^(?:[0-9]+\.|-) \S',entry,re.M):raise ValueError('Newest changelog entry has no changes')
    if base_ref:
        base=subprocess.check_output(['git','show',f'{base_ref}:app/main.py'],cwd=ROOT,text=True)
        previous=version(base,allow_legacy=True)
        current_parts=tuple(map(int,current.split('.')));previous_parts=tuple(map(int,previous.split('.')))
        if current_parts<previous_parts or (current_parts==previous_parts and not allow_unversioned):raise ValueError('Integration revision must increase source version')
        old_changelog=subprocess.check_output(['git','show',f'{base_ref}:CHANGELOG.md'],cwd=ROOT,text=True)
        if current_parts==previous_parts:
            if changelog!=old_changelog:raise ValueError('Unversioned development must leave the shared changelog unchanged')
            old_readme=subprocess.check_output(['git','show',f'{base_ref}:README.md'],cwd=ROOT,text=True)
            if (ROOT/'README.md').read_text()!=old_readme:raise ValueError('Unversioned development must leave README.md updates to the coordinator')
        else:
            old_sections=changelog_sections(old_changelog)
            if old_sections and (len(sections)!=len(old_sections)+1 or changelog[sections[1].start():]!=old_changelog[old_sections[0].start():]):raise ValueError('Integration must prepend one entry and preserve historical changelog entries')
    if pr_number is not None:
        links=re.findall(r'\[PR #([0-9]+)\]\(https://github\.com/StealthCat/MrPatchy/pull/\1\)',entry)
        if str(pr_number) not in links:raise ValueError(f'Newest changelog entry must link PR #{pr_number}')
    return current


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--base-ref')
    parser.add_argument('--allow-unversioned',action='store_true',help='Allow unchanged release metadata for a development PR; never use as the merge gate')
    parser.add_argument('--pr-number',type=int,help='Require this PR link in the new integration changelog entry')
    args=parser.parse_args()
    try:print('Source version '+check(args.base_ref,allow_unversioned=args.allow_unversioned,pr_number=args.pr_number)+' is consistent')
    except (ValueError,IndexError) as error:parser.exit(1,str(error)+'\n')
