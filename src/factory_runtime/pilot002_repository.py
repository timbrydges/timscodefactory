"""Read Git objects and authenticate their published branch binding; never run code."""
import hashlib
import os
import re
import subprocess

from factory_state.model import StateError
from .pilot002_bootstrap import facts
from .pilot002_packets import FILES, parse_builder, digest


def _git(repository, *args):
    # Object reads do not need worktree filters/hooks, replacement objects or
    # inherited Git routing/configuration. Preserve PATH for the Git executable.
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    try:
        r = subprocess.run(['git','--no-pager','-c','core.fsmonitor=false','-C',str(repository),*args],
            env=env, capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise StateError('Pilot 002 repository read failed') from None
    if r.returncode or len(r.stdout)>65536:
        raise StateError('Pilot 002 repository object is unavailable or oversized')
    return r.returncode, r.stdout


def _inspect(repository, baseline, candidate, files):
    """Low-level object check; caller must supply the pinned contract and parsed files."""
    if (any(not isinstance(s,str) or not re.fullmatch('[0-9a-f]{40}',s) for s in (baseline,candidate)) or
            set(files)!=set(FILES)):
        raise StateError('Pilot 002 commit or source scope invalid')
    for commit in (baseline,candidate):
        if _git(repository,'cat-file','-t',commit)[1].strip()!=b'commit':
            raise StateError('Pilot 002 requires exact commit objects')
    headers=_git(repository,'cat-file','commit',candidate)[1].split(b'\n\n',1)[0].splitlines()
    if [h[7:].decode() for h in headers if h.startswith(b'parent ')]!=[baseline]:
        raise StateError('Pilot 002 candidate must be one commit directly on the approved baseline')
    changed=_git(repository,'diff-tree','--name-only','-z','--no-relative','--no-ext-diff','--no-textconv','--no-renames',
        '-r',baseline,candidate)[1].split(b'\0')
    if any(p and p not in {name.encode() for name in FILES} for p in changed):
        raise StateError('Pilot 002 candidate modifies paths outside its contract')
    hashes={}
    for name in FILES:
        raw=_git(repository,'ls-tree','-r','-z','--full-tree',candidate,'--',name)[1]
        entries=raw.split(b'\0')
        if len(entries)!=2 or entries[-1]!=b'':
            raise StateError('Pilot 002 candidate file is missing or ambiguous')
        metadata,path=entries[0].split(b'\t',1);mode,kind,oid=metadata.split()
        if mode!=b'100644' or kind!=b'blob' or path.decode()!=name:
            raise StateError('Pilot 002 candidate must contain ordinary non-executable source files')
        size=int(_git(repository,'cat-file','-s',oid.decode())[1])
        if not 0<size<=16384:raise StateError('Pilot 002 candidate blob exceeds bound')
        blob=_git(repository,'cat-file','blob',oid.decode())[1]
        if blob!=files[name].encode('utf-8'):
            raise StateError('Pilot 002 Git blob differs from the exact Builder response')
        hashes[name]=hashlib.sha256(blob).hexdigest()
    tree=_git(repository,'rev-parse',candidate+'^{tree}')[1].decode().strip()
    if not re.fullmatch('[0-9a-f]{40}',tree):raise StateError('Pilot 002 tree identity invalid')
    return {'candidate_commit':candidate,'candidate_tree':tree,'baseline_commit':baseline,
        'candidate_digest':digest(files),'files_sha256':hashes,'candidate_executed':False}


def verify_published_candidate(root, repository, *, builder_response, candidate_commit, github_read):
    """github_read must use the authenticated fixed GitHub host, not event-provided data.

No branch is created or updated. A later branch move invalidates freshness of
this observation; a future live runtime must bind and expire it explicitly.
"""
    contract,_=facts(root)
    candidate=parse_builder(builder_response,root=root)
    local=_inspect(repository,contract['baseline_commit'],candidate_commit,candidate['files'])
    prefix='repos/'+contract['repository']
    commit=github_read(prefix+'/git/commits/'+candidate_commit)
    ref=github_read(prefix+'/git/ref/heads/'+contract['branch'])
    if (not isinstance(commit,dict) or commit.get('sha')!=candidate_commit or
            not isinstance(commit.get('tree'),dict) or
            commit.get('tree',{}).get('sha')!=local['candidate_tree'] or
            not isinstance(commit.get('parents'),list) or
            not all(isinstance(p,dict) for p in commit['parents']) or
            [p.get('sha') for p in commit['parents']]!=[contract['baseline_commit']] or
            not isinstance(ref,dict) or ref.get('ref')!='refs/heads/'+contract['branch'] or
            not isinstance(ref.get('object'),dict) or
            ref.get('object',{}).get('type')!='commit' or ref['object'].get('sha')!=candidate_commit):
        raise StateError('Pilot 002 published commit, parent, tree or branch differs')
    return {'status':'PUBLISHED_CANDIDATE_BINDING_OBSERVED',**local,
        'repository':contract['repository'],'branch':contract['branch'],
        'builder_response_digest':candidate['builder_response_digest'],
        'github_observation_digest':digest({'commit':commit,'ref':ref}),
        'repository_binding_verified':True,'gate_authority':False,'production_release_authorized':False}


def verify_merged_candidate(root, repository, *, builder_response, candidate_commit,
                            merge_commit, pull_request, github_read):
    """Observe an exact two-parent merge on main; never infer approval or write state."""
    if (type(pull_request) is not int or pull_request <= 0 or
            not isinstance(merge_commit,str) or not re.fullmatch('[0-9a-f]{40}',merge_commit)):
        raise StateError('Pilot 002 merge identity invalid')
    candidate=verify_published_candidate(root,repository,builder_response=builder_response,
        candidate_commit=candidate_commit,github_read=github_read)
    prefix='repos/'+candidate['repository']
    pr=github_read(prefix+'/pulls/'+str(pull_request))
    merge=github_read(prefix+'/git/commits/'+merge_commit)
    main=github_read(prefix+'/git/ref/heads/main')
    try:
        valid=(pr['number']==pull_request and type(pr['number']) is int and
            pr['merged'] is True and pr['state']=='closed' and
            pr['merge_commit_sha']==merge_commit and
            pr['head']['sha']==candidate_commit and pr['head']['ref']==candidate['branch'] and
            pr['head']['repo']['full_name']==candidate['repository'] and
            pr['base']['ref']=='main' and pr['base']['repo']['full_name']==candidate['repository'] and
            merge['sha']==merge_commit and merge['tree']['sha']==candidate['candidate_tree'] and
            [parent['sha'] for parent in merge['parents']]==[candidate['baseline_commit'],candidate_commit] and
            main['ref']=='refs/heads/main' and main['object']['type']=='commit' and
            main['object']['sha']==merge_commit)
    except (KeyError,TypeError):
        valid=False
    if not valid:
        raise StateError('Pilot 002 merged PR, tree, parents or main differs')
    return {**candidate,'status':'MERGED_CANDIDATE_BINDING_OBSERVED',
        'pull_request':pull_request,'merge_commit':merge_commit,
        'merge_observation_digest':digest({'pr':pr,'merge':merge,'main':main}),
        'owner_authorization_verified':False,'factory_state_advanced':False}
