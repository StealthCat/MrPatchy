"""Compare bounded, immutable startup inventories; differences are not malware verdicts."""
import re
from pathlib import PurePosixPath


def path_ok(value):
    return (isinstance(value,str) and 1<len(value)<=4096 and value.startswith('/')
            and not value.startswith('//') and '\x00' not in value
            and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts)


def validate(inventory):
    if not isinstance(inventory,dict) or inventory.get('state') not in ('collected','incomplete'):
        raise ValueError('Invalid persistence inventory')
    scope=inventory.get('scope');entries=inventory.get('entries');gaps=inventory.get('gaps');missing=inventory.get('missing_roots')
    if not isinstance(scope,list) or not 1<=len(scope)<=32 or not all(path_ok(p) for p in scope) or len(set(scope))!=len(scope):
        raise ValueError('Invalid persistence scope')
    if not isinstance(entries,list) or len(entries)>256 or not isinstance(gaps,list) or len(gaps)>50 or not all(isinstance(g,str) and len(g)<=8192 for g in gaps):
        raise ValueError('Invalid persistence coverage')
    if not isinstance(missing,list) or any(p not in scope for p in missing):raise ValueError('Invalid missing persistence roots')
    if type(inventory.get('skipped')) is not int or inventory['skipped']<0:raise ValueError('Invalid persistence skipped count')
    seen=set()
    for row in entries:
        if not isinstance(row,dict) or not path_ok(row.get('path')):raise ValueError('Invalid persistence path')
        path=row['path']
        if path in seen or not any(path==root or path.startswith(root+'/') for root in scope):raise ValueError('Duplicate or out-of-scope persistence entry')
        if any(path==root or path.startswith(root+'/') for root in missing):raise ValueError('Entry under missing persistence root')
        seen.add(path)
        if any(type(row.get(k)) is not int or row[k]<0 for k in ('uid','gid','mode','size','mtime_ns')) or row['mode']>0o7777:
            raise ValueError('Invalid persistence metadata')
        if row.get('kind')=='regular':
            if not isinstance(row.get('sha256'),str) or not re.fullmatch('[a-f0-9]{64}',row['sha256']):raise ValueError('Invalid persistence hash')
        elif row.get('kind')=='symlink':
            if not isinstance(row.get('target'),str) or not 1<=len(row['target'])<=4096 or '\x00' in row['target']:raise ValueError('Invalid persistence link')
        else:raise ValueError('Invalid persistence entry type')
    if inventory['state']=='collected' and (gaps or inventory['skipped']):raise ValueError('Persistence coverage contradicts collected state')


def compare(before,after):
    result={'state':'unavailable','changes':[], 'note':'No comparable complete prior inventory; absence is not evidence of removal.'}
    try:validate(before);validate(after)
    except ValueError:return result
    if before['state']!='collected' or after['state']!='collected':return result
    if set(before['scope'])!=set(after['scope']):
        return {**result,'note':'Inventory scope changed; collect another complete inventory with the same scope.'}
    old={r['path']:r for r in before['entries']};new={r['path']:r for r in after['entries']}
    changes=[]
    fields=('kind','sha256','target','uid','gid','mode','size')
    for path in sorted(old.keys()|new.keys()):
        previous=old.get(path);current=new.get(path)
        changed=[key for key in fields if (previous or {}).get(key)!=(current or {}).get(key)]
        if previous is None or current is None or changed:
            changes.append({'path':path,'kind':'added' if previous is None else 'removed' if current is None else 'changed',
                            'fields':changed,'before':previous,'after':current})
    return {'state':'compared','changes':changes,'note':'Observed changes between complete inventories, not an approved baseline or a malware verdict. Modification time alone is ignored.'}
