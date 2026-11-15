// Nur lesende Drive- und Sheets-Aufrufe für access-read. Hier gibt es ausschließlich GET auf feste Pfade; jede
// schreibende Funktion gehört in src/drive.js bzw. src/sheets.js, nie hierher (test/read-only.test.mjs prüft das).

export const DRIVE = 'https://www.googleapis.com/drive/v3/';
export const SHEETS = 'https://sheets.googleapis.com/v4/spreadsheets/';

const ID = /^[A-Za-z0-9_-]{10,200}$/;
const DRIVE_PATH = /^(about|files|files\/[A-Za-z0-9_-]+|files\/[A-Za-z0-9_-]+\/export)$/;
const SHEETS_PATH = /^[A-Za-z0-9_-]+(\/values\/[^/?#]+)?$/;
/** Obergrenze für einen Download in den Speicher (Bytes). */
export const MAX_DOWNLOAD = 50 * 1024 * 1024;

export class GoogleReadError extends Error {
  constructor(message, { status = null } = {}) { super(message); this.name = 'GoogleReadError'; this.status = status; }
}

/** ID aus einer ID oder einer Google-URL (…/d/<id>/…, …/folders/<id>, ?id=<id>). */
export function idFrom(x) {
  const s = String(x ?? '').trim();
  const m = /\/d\/([A-Za-z0-9_-]+)/.exec(s) ?? /\/folders\/([A-Za-z0-9_-]+)/.exec(s) ?? /[?&]id=([A-Za-z0-9_-]+)/.exec(s);
  const id = m ? m[1] : s;
  if (!ID.test(id)) throw new GoogleReadError(`keine gültige Google-ID: ${s.replace(/[^A-Za-z0-9/:._?=&-]/g, '').slice(0, 80)}`);
  return id;
}

// Downloads (raw) bekommen mehr Zeit: das Zeitlimit gilt auch für das Lesen des Inhalts.
async function get(base, path, re, { token, params = {}, fetchImpl = fetch, raw = false, timeoutMs = raw ? 180_000 : 30_000 }) {
  if (!token) throw new GoogleReadError('kein Zugangstoken');
  if (!re.test(path)) throw new GoogleReadError(`Lesepfad ${String(path).slice(0, 60)} nicht erlaubt`);
  const u = new URL(base + path);
  for (const [k, v] of Object.entries(params)) if (v != null) u.searchParams.set(k, String(v));
  let res;
  try {
    res = await fetchImpl(u.href, { method: 'GET', headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) { throw new GoogleReadError(`Google nicht erreichbar: ${e?.cause?.code ?? e?.name ?? 'Fehler'}`); }
  if (!res.ok) {
    let msg = String(res.status);
    try { msg = String((await res.json())?.error?.message ?? res.status); } catch { /* kein JSON */ }
    throw new GoogleReadError(`Google API ${res.status}: ${msg.slice(0, 200)}`, { status: res.status });
  }
  if (raw) return res;
  let json;
  try { json = await res.json(); } catch { throw new GoogleReadError('Google-Antwort ist kein JSON'); }
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw new GoogleReadError('Google-Antwort unvollständig');
  return json;
}

const driveGet = (path, o) => get(DRIVE, path, DRIVE_PATH, o);
const ALL = { supportsAllDrives: 'true' };
const FILE_FIELDS = 'id,name,mimeType,size,modifiedTime,parents,owners(emailAddress),webViewLink,trashed';

/** Adresse, zu der der Token gehört (Drive about). */
export async function driveWhoami({ token, fetchImpl }) {
  const j = await driveGet('about', { token, fetchImpl, params: { fields: 'user(emailAddress)' } });
  return String(j?.user?.emailAddress ?? '').toLowerCase();
}

/** Dateien zu einer Drive-Suche `q` (Drive-Abfragesprache), höchstens max. */
export async function driveQuery({ token, q, max = 50, fetchImpl }) {
  const out = [];
  let pageToken;
  do {
    const j = await driveGet('files', {
      token, fetchImpl,
      params: { ...ALL, q, corpora: 'allDrives', includeItemsFromAllDrives: 'true', pageSize: Math.min(100, max - out.length), pageToken, fields: `nextPageToken,incompleteSearch,files(${FILE_FIELDS})` },
    });
    if (!Array.isArray(j.files ?? [])) throw new GoogleReadError('Drive-Liste ohne files');
    out.push(...(j.files ?? []));
    pageToken = j.nextPageToken;
    if (out.length >= max) return { files: out.slice(0, max), truncated: Boolean(pageToken) || out.length > max, incomplete: Boolean(j.incompleteSearch) };
    if (j.incompleteSearch) return { files: out, truncated: false, incomplete: true };
  } while (pageToken);
  return { files: out, truncated: false, incomplete: false };
}

const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
export const nameQuery = (text) => `name contains '${esc(text)}' and trashed = false`;
export const folderQuery = (id) => `'${esc(idFrom(id))}' in parents and trashed = false`;

export const driveInfo = ({ token, id, fetchImpl }) => driveGet(`files/${idFrom(id)}`, { token, fetchImpl, params: { ...ALL, fields: FILE_FIELDS } });

/** Google-eigene Formate → Exportformat. */
export const EXPORT = Object.freeze({
  'application/vnd.google-apps.document': { mime: 'text/plain', ext: 'txt', text: true },
  'application/vnd.google-apps.spreadsheet': { mime: 'text/csv', ext: 'csv', text: true },
  'application/vnd.google-apps.presentation': { mime: 'text/plain', ext: 'txt', text: true },
  'application/vnd.google-apps.drawing': { mime: 'application/pdf', ext: 'pdf', text: false },
});
const TEXT_MIME = /^(text\/|application\/(json|xml|csv|x-yaml|yaml|javascript))/;

/**
 * Inhalt einer Datei. Google-Dokumente werden exportiert (Doc/Slides als Text, Sheet als CSV des ersten Tabs).
 * @returns {Promise<{ info: object, bytes: Buffer, text: boolean, mime: string }>}
 */
export async function driveDownload({ token, id, fetchImpl, maxBytes = MAX_DOWNLOAD }) {
  const info = await driveInfo({ token, id, fetchImpl });
  if (info.trashed) throw new GoogleReadError('Datei liegt im Papierkorb');
  if (info.mimeType === 'application/vnd.google-apps.folder') throw new GoogleReadError('ist ein Ordner: drive list <ordner-id>');
  const ex = EXPORT[info.mimeType];
  if (!ex && String(info.mimeType).startsWith('application/vnd.google-apps.')) throw new GoogleReadError(`Google-Format ${info.mimeType} lässt sich nicht exportieren`);
  if (!ex && Number(info.size) > maxBytes) throw new GoogleReadError(`Datei größer als ${Math.round(maxBytes / 1048576)} MB`);
  const res = ex
    ? await driveGet(`files/${info.id}/export`, { token, fetchImpl, params: { mimeType: ex.mime }, raw: true })
    : await driveGet(`files/${info.id}`, { token, fetchImpl, params: { ...ALL, alt: 'media' }, raw: true });
  const bytes = await readCapped(res, maxBytes);
  const mime = ex ? ex.mime : String(info.mimeType);
  return { info, bytes, text: ex ? ex.text : TEXT_MIME.test(mime), mime };
}

/** Antwort lesen und beim Überschreiten von maxBytes abbrechen, statt erst alles in den Speicher zu laden. */
export async function readCapped(res, maxBytes) {
  const zuGross = () => new GoogleReadError(`Datei größer als ${Math.round(maxBytes / 1048576)} MB`);
  if (!res.body?.getReader) {
    const b = Buffer.from(await res.arrayBuffer());
    if (b.length > maxBytes) throw zuGross();
    return b;
  }
  const reader = res.body.getReader();
  const teile = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > maxBytes) { await reader.cancel().catch(() => {}); throw zuGross(); }
    teile.push(value);
  }
  return Buffer.concat(teile);
}

const sheetsGet = (path, o) => get(SHEETS, path, SHEETS_PATH, o);

/** Tabs eines Sheets: [{ title, sheetId, rows, columns }]. */
export async function sheetTabs({ token, id, fetchImpl }) {
  const j = await sheetsGet(idFrom(id), { token, fetchImpl, params: { fields: 'properties(title),sheets.properties(sheetId,title,gridProperties(rowCount,columnCount))' } });
  return { title: j.properties?.title ?? null, tabs: (j.sheets ?? []).map((s) => ({ title: s.properties?.title, sheetId: s.properties?.sheetId ?? 0, rows: s.properties?.gridProperties?.rowCount ?? null, columns: s.properties?.gridProperties?.columnCount ?? null })) };
}

/** Werte eines Bereichs (A1, z. B. „Tab!A1:F50“). */
export async function sheetValues({ token, id, range, unformatted = false, fetchImpl }) {
  if (!range || String(range).length > 300) throw new GoogleReadError('Bereich fehlt oder zu lang');
  const j = await sheetsGet(`${idFrom(id)}/values/${encodeURIComponent(String(range))}`, { token, fetchImpl, params: { valueRenderOption: unformatted ? 'UNFORMATTED_VALUE' : 'FORMATTED_VALUE' } });
  return { range: j.range ?? range, values: j.values ?? [] };
}
