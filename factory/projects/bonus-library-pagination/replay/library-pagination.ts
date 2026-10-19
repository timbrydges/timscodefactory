import type { SupabaseClient } from "@supabase/supabase-js";

export const PAGE_SIZE = 10;
type Cursor = { direction: "older" | "newer"; created_at: string; id: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const timestamp = /^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?(?:Z|\+00:00)$/;
const columns = "id,title,description,status,source_object_path,source_sha256,source_size_bytes,cover_object_path,metadata_sha256,created_at";

export function decodeCursor(input: string | string[] | undefined): Cursor | null {
  if (input === undefined) return null;
  if (typeof input !== "string" || !/^[A-Za-z0-9_-]{1,512}$/.test(input)) throw new Error("Invalid page");
  const bytes = Buffer.from(input, "base64url");
  if (bytes.toString("base64url") !== input) throw new Error("Invalid page");
  const value = JSON.parse(bytes.toString("utf8"));
  if (!value || Object.keys(value).sort().join(",") !== "created_at,direction,id"
      || !["older", "newer"].includes(value.direction)
      || typeof value.id !== "string" || !uuid.test(value.id)
      || typeof value.created_at !== "string" || !timestamp.test(value.created_at)
      || !Number.isFinite(Date.parse(value.created_at))
      || new Date(value.created_at).toISOString().slice(0,10) !== value.created_at.slice(0,10)) {
    throw new Error("Invalid page");
  }
  return value;
}

function link(direction: Cursor["direction"], row: { id: string; created_at: string }) {
  const token = Buffer.from(JSON.stringify({ direction, id: row.id, created_at: row.created_at })).toString("base64url");
  decodeCursor(token);
  return `/dashboard?cursor=${token}`;
}

export async function loadLibraryPage(client: SupabaseClient, ownerId: string, input: string | string[] | undefined) {
  const empty = { items: [], older: null, newer: null };
  let cursor: Cursor | null;
  try { cursor = decodeCursor(input); } catch { return { ...empty, status: "invalid" as const }; }
  if (!uuid.test(ownerId)) return { ...empty, status: "error" as const };
  const ascending = cursor?.direction === "newer";
  let query = client.from("library_items").select(columns).eq("owner_id", ownerId)
    .order("created_at", { ascending }).order("id", { ascending }).limit(PAGE_SIZE + 1);
  if (cursor) {
    const op = ascending ? "gt" : "lt";
    // Only strict timestamp/UUID values reach this raw PostgREST expression.
    query = query.or(`created_at.${op}.${cursor.created_at},and(created_at.eq.${cursor.created_at},id.${op}.${cursor.id})`);
  }
  try {
    const { data, error } = await query;
    if (error || !data) return { ...empty, status: "error" as const };
    const extra = data.length > PAGE_SIZE;
    const items = data.slice(0, PAGE_SIZE);
    if (ascending) items.reverse();
    return { status: "ok" as const, items,
      older: items.length && (ascending || extra) ? link("older", items[items.length - 1]) : null,
      newer: items.length && (ascending ? extra : cursor !== null) ? link("newer", items[0]) : null };
  } catch { return { ...empty, status: "error" as const }; }
}
