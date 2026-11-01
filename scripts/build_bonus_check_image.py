"""Owner-run build of the offline Bonus Library check image.

Takes package.json and package-lock.json from the exact pinned commit (via the
owner's own Git login), installs them with `npm ci --ignore-scripts` on a
digest-pinned Node base image, and prints the content-addressed image ID used
by development attempts. The image holds dependencies only; repository source is
mounted per attempt. Building needs network access once; attempts run offline.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

REPOSITORY = 'https://github.com/timbrydges/bonus-library.git'
PINNED_COMMIT = 'ef88df95bc3f046d080af51e3654d2259759072b'
PINNED_BASE = 'node@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da'
DOCKERFILE = """FROM {base}
WORKDIR /deps
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
"""


def run(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=1800, **kw).stdout


def build(*, commit, base, workdir, runner=run, out=print):
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', base):
        raise ValueError('exact commit and digest-pinned base image required')
    work = Path(workdir)
    clone, context = work/'source', work/'context'
    context.mkdir()
    runner(['git', 'clone', '--quiet', '--no-checkout', '--filter=blob:none', REPOSITORY, str(clone)])
    for name in ('package.json', 'package-lock.json'):
        (context/name).write_bytes(runner(['git', '-C', str(clone), 'show', f'{commit}:{name}']).encode('utf-8'))
    (context/'Dockerfile').write_text(DOCKERFILE.format(base=base), encoding='utf-8')
    tag = f'factory-bonus-checks:{commit[:12]}'
    out(f'Building {tag} (installs npm dependencies; this can take a few minutes)...')
    runner(['docker', 'build', '--pull=false', '-t', tag, str(context)])
    image_id = runner(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}']).strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('Docker did not report a content-addressed image ID')
    out(f'Built {tag} = {image_id}')
    out(f'Next: run_owner_attempt.py uses --image {tag} by default.')
    return {'tag': tag, 'image_id': image_id}


def main(argv=None, runner=run):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-authorized', action='store_true')
    parser.add_argument('--commit', default=PINNED_COMMIT)
    parser.add_argument('--base', default=PINNED_BASE)
    args = parser.parse_args(argv)
    if not args.owner_authorized:
        parser.error('explicit owner authorization required')
    with tempfile.TemporaryDirectory(prefix='factory-image-') as workdir:
        build(commit=args.commit, base=args.base, workdir=workdir, runner=runner)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except subprocess.CalledProcessError as error:
        print(f'STOPPED: {error.cmd[0]} failed (exit {error.returncode}). {str(error.stderr or "")[-800:]}')
        raise SystemExit(1)
    except Exception as error:
        print(f'STOPPED: {type(error).__name__}: {str(error)[:300]}')
        raise SystemExit(1)
