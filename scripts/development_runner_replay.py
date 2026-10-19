"""Offline acceptance replay against pinned Bonus Library Git objects.

Hand-authored proposal and deterministic review are explicitly NOT a live model
proof. Actual pagination tests execute in the network-disabled Docker sandbox.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.development_runner import DevelopmentTaskRunner
from factory_runtime.docker_sandbox import DockerSandboxAdapter, DockerSandboxPolicy
from factory_runtime.repository_snapshot import read_repository_snapshot
from factory_runtime.task_queue import LocalTaskQueue, QueuedTask
from factory_runtime.worker import digest


def proposal(snapshot):
    replay = ROOT / 'factory/projects/bonus-library-pagination/replay'
    path = 'src/app/dashboard/page.tsx'
    original = next(f.content.decode('utf-8') for f in snapshot.files if f.path == path)
    replacements = [
        ('export default async function DashboardPage() {',
         'export default async function DashboardPage({ searchParams }: { searchParams: Promise<{ cursor?: string | string[] }> }) {\n  const { cursor } = await searchParams;'),
        ('import { createClient } from "@/lib/supabase/server";',
         'import { createClient } from "@/lib/supabase/server";\nimport { loadLibraryPage } from "@/lib/library-pagination";'),
        ('const [{ data: ownerBinding, error: ownerError }, { data: drafts }] = await Promise.all([',
         'const [{ data: ownerBinding, error: ownerError }, page] = await Promise.all(['),
        ('    supabase\n      .from("library_items")\n      .select("id,title,description,status,source_object_path,source_sha256,source_size_bytes,cover_object_path,metadata_sha256,created_at")\n      .eq("owner_id", ownerId)\n      .order("created_at", { ascending: false })\n      .limit(10),',
         '    loadLibraryPage(supabase, ownerId, cursor),'),
        ('  const ownerActive =', '  const drafts = page.items;\n  const ownerActive ='),
        ('              {drafts?.length ? (',
         '              {page.status !== "ok" ? (\n                <p role="alert">{page.status === "invalid" ? "Invalid page link." : "Could not load library items. Please try again."} <a href="/dashboard">Return to newest items</a></p>\n              ) : drafts.length ? ('),
        ('<p className="empty">No items yet. Your first upload will appear here.</p>',
         '<p className="empty">{cursor ? "No items on this page." : "No items yet. Your first upload will appear here."} <a href="/dashboard">Newest items</a></p>'),
        ('              )}\n            </section>\n          </div>',
         '              )}\n              {page.status === "ok" ? (\n                <nav aria-label="Library pages">\n                  {page.newer ? <a href={page.newer}>Newer</a> : null}{" "}\n                  {page.older ? <a href={page.older}>Older</a> : null}\n                </nav>\n              ) : null}\n            </section>\n          </div>'),
    ]
    updated = original
    for old, new in replacements:
        if updated.count(old) != 1:
            raise ValueError('pinned dashboard differs from replay replacement')
        updated = updated.replace(old, new, 1)
    edits = [{'path': path, 'old_text': original, 'new_text': updated}]
    for destination in ['src/lib/library-pagination.ts', 'tests/library-pagination.test.mjs']:
        edits.append({'path': destination, 'old_text': '',
                      'new_text': (replay / Path(destination).name).read_text(encoding='utf-8')})
    return {'type': 'apply_edits', 'summary': 'Owner-scoped keyset pagination with Older/Newer links', 'edits': edits}


async def run(image_ref, output):
    # Exclusive output prevents accidentally overwriting a previous attempt's evidence.
    output.mkdir(parents=True, exist_ok=False)
    raw = (ROOT / 'factory/projects/bonus-library-pagination/task.json').read_bytes()
    spec = json.loads(raw)
    bundle = ROOT / 'factory/projects/bonus-library-pagination/replay/source.bundle'
    with TemporaryDirectory(prefix='factory-replay-') as directory:
        database = Path(directory) / 'source.git'
        subprocess.run(['git', 'init', '--bare', str(database)],
                       check=True, capture_output=True, timeout=30)
        # Bundle holds the exact shallow acceptance commit and its complete tree,
        # not the product's history. Preserve that explicit shallow boundary.
        (database / 'shallow').write_text(spec['target_commit']+'\n', encoding='ascii')
        subprocess.run(['git', '-C', str(database), 'bundle', 'unbundle', str(bundle)],
                       check=True, capture_output=True, timeout=30)
        snapshot = read_repository_snapshot(database, repository=spec['repository'], commit=spec['target_commit'])
        decision = proposal(snapshot)
        queue = LocalTaskQueue(output / 'queue.db')
        queue.enqueue(QueuedTask('bonus-pagination-replay','offline-replay',spec['task_id'],
            'offline-replay','a'*40,digest(raw),'IMPLEMENTATION'))
        policy = DockerSandboxPolicy(image_ref=image_ref)
        async def builder(turn): return decision
        async def reviewer(turn):
            return {'review_input_digest':turn['review_input_digest'],'verdict':'APPROVE','findings':[]}
        def request(candidate):
            return candidate.request(request_id='pagination-tests',lease_id='offline-replay',
                role_id='offline-tests',command=('node','--experimental-strip-types','--test','tests/library-pagination.test.mjs'),
                environment_digest=policy.environment_digest,timeout_seconds=60,
                expected_runner_identity=policy.runner_identity)
        def save(entry, content):
            with (output / 'attempt.json').open('xb') as handle: handle.write(content)
        runner = DevelopmentTaskRunner(queue, contract_bytes=raw, snapshot=snapshot,
            builder=builder, reviewer=reviewer, request_for=request,
            sandbox_for=lambda candidate: DockerSandboxAdapter(candidate.workspace,policy),
            save_artifact=save,clock=lambda:datetime.now(timezone.utc),
            builder_identity='recorded-builder',reviewer_identity='recorded-reviewer',enabled=True)
        queue.pause(False)  # Only this new disposable local replay database.
        result = await runner.tick()
        duplicate = await runner.tick()
        result.update(proof_kind='OFFLINE_REPLAY_REAL_REPOSITORY', model_calls=0,
            independent_model_review=False, production_changed=False,
            repository=spec['repository'], target_commit=spec['target_commit'],
            source_bundle_digest=digest(bundle.read_bytes()), source_file_count=len(snapshot.files),
            repeated_tick_status=duplicate['status'])
        (output / 'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result,indent=2))
        if result['status'] != 'TICK_COMPLETED' or duplicate['status'] != 'IDLE_OR_PAUSED':
            raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-ref', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.image_ref, args.output))
