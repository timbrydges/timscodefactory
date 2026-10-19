import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { loadLibraryPage, decodeCursor } from '../src/lib/library-pagination.ts';

const owner = '00000000-0000-0000-0000-000000000001';
const foreign = '00000000-0000-0000-0000-000000000002';
const rows = Array.from({ length: 27 }, (_, i) => ({
  id: `10000000-0000-0000-0000-${String(i).padStart(12,'0')}`,
  created_at: '2026-10-01T12:00:00.123456+00:00', owner_id: owner,
}));
const token = href => href ? new URL(href,'https://example.test').searchParams.get('cursor') : undefined;
// Independent in-memory relational oracle; no API, credentials or production reads.
function client(dataset = rows, fail = false) {
  const calls = [];
  return { calls, from(table) {
    assert.equal(table,'library_items');
    const state = { orders: [] }; calls.push(state);
    const query = {
      select() { return query; },
      eq(field,value) { assert.equal(field,'owner_id'); state.owner=value; return query; },
      order(field,options) { state.orders.push([field,options.ascending]); return query; },
      limit(value) { state.limit=value; return query; },
      or(value) { state.filter=value; return query; },
      then(resolve,reject) {
        try {
          assert.equal(state.owner,owner);
          assert.equal(state.limit,11);
          const asc=state.orders[0][1];
          assert.deepEqual(state.orders,[['created_at',asc],['id',asc]]);
          let result=dataset.filter(row => row.owner_id===state.owner);
          if (state.filter) {
            const match=state.filter.match(/^created_at\.(lt|gt)\.([^,]+),and\(created_at\.eq\.([^,]+),id\.(lt|gt)\.([^)]+)\)$/);
            assert.ok(match); assert.equal(match[1],match[4]); assert.equal(match[2],match[3]);
            result=result.filter(row => match[1]==='lt'
              ? row.created_at < match[2] || row.created_at===match[2] && row.id < match[5]
              : row.created_at > match[2] || row.created_at===match[2] && row.id > match[5]);
          }
          result.sort((a,b) => (a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id)) * (asc ? 1 : -1));
          resolve({data:result.slice(0,state.limit),error:fail ? {message:'private'} : null});
        } catch (error) { reject(error); }
      },
    }; return query;
  }};
}

test('all 27 equal-timestamp items reachable both ways without duplicates or foreign rows', async () => {
  const db=client([...rows,{...rows[0],id:'ffffffff-ffff-ffff-ffff-ffffffffffff',owner_id:foreign}]);
  const first=await loadLibraryPage(db,owner,undefined);
  const second=await loadLibraryPage(db,owner,token(first.older));
  const third=await loadLibraryPage(db,owner,token(second.older));
  assert.equal(first.newer,null); assert.equal(third.older,null);
  const ids=[...first.items,...second.items,...third.items].map(r=>r.id);
  assert.equal(new Set(ids).size,27); assert.deepEqual(ids,rows.map(r=>r.id).reverse());
  const back=await loadLibraryPage(db,owner,token(third.newer));
  assert.deepEqual(back.items,second.items);
  const top=await loadLibraryPage(db,owner,token(back.newer));
  assert.deepEqual(top.items,first.items); assert.equal(top.newer,null);
});

test('timestamp boundaries and the exact final page remain stable', async () => {
  const mixed=rows.slice(0,20).map((r,i)=>({...r,created_at:`2026-10-${i<10?'01':'02'}T12:00:00Z`}));
  const db=client(mixed), first=await loadLibraryPage(db,owner,undefined);
  const last=await loadLibraryPage(db,owner,token(first.older));
  assert.equal(last.items.length,10); assert.equal(last.older,null);
  assert.deepEqual((await loadLibraryPage(db,owner,token(last.newer))).items,first.items);
});

test('malformed, duplicate and injection cursors cannot issue queries or change owner', async () => {
  const db=client();
  for (const value of ['',[],['a','b'],'a'.repeat(513),'abc=',Buffer.from(JSON.stringify({direction:'older',id:owner,created_at:'2026-02-30T00:00:00Z'})).toString('base64url'),
    Buffer.from(JSON.stringify({direction:'older',id:'x),owner_id.eq.other',created_at:rows[0].created_at})).toString('base64url')]) {
    assert.equal((await loadLibraryPage(db,owner,value)).status,'invalid');
  }
  assert.equal(db.calls.length,0);
  assert.equal((await loadLibraryPage(db,'bad-owner',undefined)).status,'error');
  assert.equal(db.calls.length,0);
  assert.equal(decodeCursor(undefined),null);
});

test('empty, stale page and failed reads are explicit', async () => {
  const first=await loadLibraryPage(client(),owner,undefined);
  assert.deepEqual((await loadLibraryPage(client([]),owner,token(first.older))).items,[]);
  assert.equal((await loadLibraryPage(client([]),owner,undefined)).status,'ok');
  assert.equal((await loadLibraryPage(client(rows,true),owner,undefined)).status,'error');
});

test('dashboard preserves owner controls and exposes accessible error/navigation states', () => {
  const page=readFileSync(new URL('../src/app/dashboard/page.tsx',import.meta.url),'utf8');
  for(const required of ['getClaims()', 'ownerActive ?', '<SourceUploadForm', '<DraftInspector', '<DraftReview',
    'await searchParams', 'loadLibraryPage(supabase, ownerId, cursor)', 'role="alert"', 'aria-label="Library pages"', '>Older</a>', '>Newer</a>']) assert.ok(page.includes(required),required);
});
