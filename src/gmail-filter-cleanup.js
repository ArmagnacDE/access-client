// Alte Betreff-Sperrfilter früherer Merkmal-Listen entfernen (S137 „Mail-Wächter-Job live“; Auftrag Orchestrator, Löschen
// ist feste Grenze und läuft nur per Freigabe). Jede neue Liste legt mit security-label.mjs --apply neue Filter an,
// die alten bleiben stehen (je Postfach v1.3, v1.4, v1.5.0). Dieses Modul löscht genau die Filter, die
//   1. in der Stand-Datei eines --apply-Laufs (Vorher-Stand) stehen,
//   2. reine Betreff-Sperrfilter der Liste sind (nur criteria.query „subject:("password reset" …)“, Aktion nur
//      addLabelIds mit genau einem Label) und nicht einer der aktuellen SECURITY_FILTERS,
//   3. im Postfach noch genau so stehen (Kriterium und Aktion unverändert),
// und nur, wenn alle aktuellen Sicherheitsfilter mit demselben Label im Postfach stehen (nie alten Schutz entfernen,
// bevor der neue steht). Vor jedem DELETE meldet onBackup den ganzen Filter (Kriterium, Aktion), damit restoreFilters
// ihn wieder anlegen kann. Schreibend nur: DELETE settings/filters/<id> und (restore) POST settings/filters.
import { assertNoSend } from './gmail.js';
import { SECURITY_FILTERS } from './gmail-setup.js';

const USERS = 'https://gmail.googleapis.com/gmail/v1/users/';
const MAILBOX = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;
const FILTER_ID = /^[A-Za-z0-9_-]{1,200}$/;
const ALTE_LISTE = /^subject:\("password reset" OR /;

async function call({ token, mailbox, path, method = 'GET', body, fetchImpl }) {
  if (!MAILBOX.test(String(mailbox))) throw new Error(`Filter-Aufräumen: Postfach ${String(mailbox).slice(0, 60)} ungültig`);
  assertNoSend(path); assertNoSend(mailbox);
  const m = /^settings\/filters\/(.+)$/.exec(path);
  const erlaubt = (method === 'GET' && path === 'settings/filters') || (method === 'POST' && path === 'settings/filters')
    || (method === 'DELETE' && m && FILTER_ID.test(m[1]));
  if (!erlaubt) throw new Error(`Filter-Aufräumen: ${method} ${path.slice(0, 80)} nicht erlaubt (ID?)`);
  let res;
  try {
    res = await fetchImpl(`${USERS}${encodeURIComponent(mailbox)}/${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'error', signal: AbortSignal.timeout(30_000),
    });
  } catch (e) { throw new Error(`Filter-Aufräumen: ${mailbox} nicht erreichbar (${e?.cause?.code ?? e?.name ?? 'Fehler'})`); }
  const roh = await res.text().catch(() => '');
  let j = null;
  try { j = roh && roh.trim() ? JSON.parse(roh) : {}; } catch { j = null; }
  if (!res.ok) throw new Error(`Filter-Aufräumen ${method} ${path} in ${mailbox}: API ${res.status} ${String(j?.error?.message ?? '').slice(0, 160)}`);
  if (!j || typeof j !== 'object') throw new Error(`Filter-Aufräumen ${method} ${path}: Antwort unvollständig`);
  return j;
}

const gleich = (a, b) => JSON.stringify({ c: a?.criteria ?? null, a: a?.action ?? null }) === JSON.stringify({ c: b?.criteria ?? null, a: b?.action ?? null });
const aktuelleQueries = new Set(SECURITY_FILTERS.map((s) => s.criteria.query).filter(Boolean));

/** Alte Betreff-Sperrfilter aus einem Postfach-Eintrag der Stand-Datei ({ mailbox, before: { filters } }). */
export function oldFilterCandidates(eintrag) {
  return (eintrag?.before?.filters ?? []).filter((f) => {
    const c = f?.criteria ?? {}; const a = f?.action ?? {};
    return FILTER_ID.test(String(f?.id)) && Object.keys(c).length === 1 && typeof c.query === 'string' && ALTE_LISTE.test(c.query)
      && !aktuelleQueries.has(c.query) && Object.keys(a).length === 1 && Array.isArray(a.addLabelIds) && a.addLabelIds.length === 1;
  }).map((f) => ({ id: f.id, criteria: f.criteria, action: f.action }));
}

/** Nur lesend: was gelöscht würde (delete), was schon weg ist (gone), was sich geändert hat (changed, bleibt). */
export async function planFilterCleanup({ token, mailbox, candidates, fetchImpl = fetch }) {
  const filters = (await call({ token, mailbox, path: 'settings/filters', fetchImpl })).filter ?? [];
  const byId = new Map(filters.map((f) => [f.id, f]));
  const out = { mailbox, delete: [], gone: [], changed: [], blocked: null };
  for (const c of candidates) {
    const live = byId.get(c.id);
    if (!live) out.gone.push(c.id);
    else if (!gleich(live, c)) out.changed.push(c.id);
    else out.delete.push({ id: live.id, criteria: live.criteria, action: live.action });
  }
  const labels = new Set(out.delete.map((f) => f.action.addLabelIds[0]));
  const fehlt = [...labels].flatMap((l) => SECURITY_FILTERS.filter((sf) => !filters.some((x) => JSON.stringify(x.criteria) === JSON.stringify(sf.criteria)
    && (x.action?.addLabelIds ?? []).includes(l))).map((sf) => sf.name));
  if (fehlt.length) { out.blocked = `neue Filter fehlen (${[...new Set(fehlt)].join(', ')}); alte bleiben`; out.delete = []; }
  return out;
}

/** Löscht, was planFilterCleanup freigibt; onBackup(filter) vor, onDeleted(id) nach jedem DELETE. */
export async function removeOldFilters({ token, mailbox, candidates, fetchImpl = fetch, onBackup = () => {}, onDeleted = () => {} }) {
  for (const c of candidates) if (!FILTER_ID.test(String(c?.id))) throw new Error(`Filter-Aufräumen: ID „${String(c?.id).slice(0, 40)}“ ungültig`);
  const plan = await planFilterCleanup({ token, mailbox, candidates, fetchImpl });
  const deleted = [];
  for (const f of plan.delete) {
    onBackup(f);
    await call({ token, mailbox, path: `settings/filters/${f.id}`, method: 'DELETE', fetchImpl });
    deleted.push(f.id);
    onDeleted(f.id);
  }
  return { ...plan, deleted };
}

/** Legt gesicherte Filter wieder an (Kriterium und Aktion), außer ein gleicher steht schon da. */
export async function restoreFilters({ token, mailbox, filters, fetchImpl = fetch, dryRun = false }) {
  const live = (await call({ token, mailbox, path: 'settings/filters', fetchImpl })).filter ?? [];
  const created = []; const skipped = [];
  for (const f of filters) {
    if (live.some((x) => gleich(x, f))) { skipped.push(f.id); continue; }
    if (dryRun) { created.push({ alt: f.id, id: null }); continue; }
    const r = await call({ token, mailbox, path: 'settings/filters', method: 'POST', fetchImpl, body: { criteria: f.criteria, action: f.action } });
    created.push({ alt: f.id, id: r.id ?? null });
    live.push({ ...f, id: r.id });
  }
  return { mailbox, created, skipped };
}
