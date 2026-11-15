// Minimal Google Drive API v3 helper. No external deps.
// Lesen, Hochladen, Kopieren, Verschieben, Freigaben (access-client).

import { getAccessToken } from './google-auth.js';

const API = 'https://www.googleapis.com/drive/v3';

async function api(path) {
  const at = await getAccessToken();
  const res = await fetch(API + path, { headers: { Authorization: 'Bearer ' + at } });
  if (!res.ok) throw new Error(`Drive API ${res.status}: ${await res.text()}`);
  return res.json();
}

// List non-trashed direct children of a folder (incl. shared drives). Paginiert
// über nextPageToken — sonst liefert ein Ordner mit >1000 Kindern nur die erste Seite
// (Kollisionscheck/Verifikation im Image-Match würden sonst Dateien übersehen).
// extraFields: zusaetzliche Datei-Felder, z. B. 'appProperties' (erkennt so schon kopierte Dateien).
// vollstaendig: true → bricht ab, wenn Drive `incompleteSearch` meldet (bei corpora=allDrives
// dokumentiert möglich, unabhängig von der Pagination). Für Aufrufer, die aus „nicht gelistet“
// Schlüsse ziehen (Bremse, Kollisionsprüfung).
export async function listChildren(folderId, extraFields = '', { vollstaendig = false } = {}) {
  const q = encodeURIComponent(`'${folderId}' in parents and trashed=false`);
  const extra = 'supportsAllDrives=true&includeItemsFromAllDrives=true&corpora=allDrives';
  const out = [];
  let pageToken = '';
  do {
    const pt = pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : '';
    // imageMediaMetadata liefert Breite/Hoehe fuer Bilddateien, ohne sie herunterzuladen —
    // damit laesst sich das Seitenverhaeltnis pruefen, BEVOR etwas hochgeladen wird.
    const felder = `${vollstaendig ? 'incompleteSearch,' : ''}nextPageToken,files(id,name,mimeType,imageMediaMetadata(width,height)${extraFields ? ',' + extraFields : ''})`;
    const json = await api(`/files?q=${q}&fields=${felder}&pageSize=1000&${extra}${pt}`);
    if (vollstaendig && json.incompleteSearch) throw new Error(`Drive-Liste von ${folderId} unvollständig (incompleteSearch)`);
    out.push(...(json.files || []));
    pageToken = json.nextPageToken || '';
  } while (pageToken);
  return out;
}

// Download a file's raw text content.
export async function downloadText(fileId) {
  const at = await getAccessToken();
  const res = await fetch(`${API}/files/${fileId}?alt=media`, {
    headers: { Authorization: 'Bearer ' + at },
  });
  if (!res.ok) throw new Error(`Drive download ${res.status}: ${await res.text()}`);
  return res.text();
}

// Download a file's raw bytes (Buffer) — für Bilder u.ä.
export async function downloadBytes(fileId) {
  const at = await getAccessToken();
  const res = await fetch(`${API}/files/${fileId}?alt=media&supportsAllDrives=true`, {
    headers: { Authorization: 'Bearer ' + at },
  });
  if (!res.ok) throw new Error(`Drive download ${res.status}: ${await res.text()}`);
  return Buffer.from(await res.arrayBuffer());
}

export const FOLDER_MIME = 'application/vnd.google-apps.folder';

// Eine Datei in einen anderen Ordner verschieben (Parent tauschen). Verschiebt, kopiert
// NICHT — die Datei-ID bleibt gleich. removeParent = bisheriger Ordner (Quelle).
export async function moveFile(fileId, addParent, removeParent) {
  const at = await getAccessToken();
  const qs = new URLSearchParams({
    addParents: addParent, removeParents: removeParent,
    supportsAllDrives: 'true', fields: 'id,name,parents',
  });
  const res = await fetch(`${API}/files/${fileId}?${qs}`, {
    method: 'PATCH', headers: { Authorization: 'Bearer ' + at },
  });
  if (!res.ok) throw new Error(`Drive move ${res.status}: ${await res.text()}`);
  return res.json();
}

// Delete a file or folder by id.
export async function deleteFile(id) {
  const at = await getAccessToken();
  const res = await fetch(`${API}/files/${id}?supportsAllDrives=true`, {
    method: 'DELETE', headers: { Authorization: 'Bearer ' + at },
  });
  if (!res.ok && res.status !== 204) throw new Error(`Drive delete ${res.status}: ${await res.text()}`);
}

// Metadaten einer Datei lesen, z. B. fields='id,name,size,md5Checksum,parents,trashed'.
export async function getFile(id, fields = 'id,name,size,md5Checksum,parents,trashed') {
  return api(`/files/${id}?supportsAllDrives=true&fields=${encodeURIComponent(fields)}`);
}

// Metadaten ändern (z. B. { description } oder { trashed: true }). Nur Metadaten, kein Inhalt.
export async function updateMetadata(id, meta) {
  const at = await getAccessToken();
  const res = await fetch(`${API}/files/${id}?supportsAllDrives=true&fields=id,name,trashed`, {
    method: 'PATCH',
    headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify(meta),
  });
  if (!res.ok) throw new Error(`Drive update ${res.status}: ${await res.text()}`);
  return res.json();
}

// In den Papierkorb legen (wiederherstellbar, in Shared Drives 30 Tage) — anders als deleteFile,
// das endgültig löscht.
export const trashFile = (id) => updateMetadata(id, { trashed: true });

async function apiPost(url, body, contentType) {
  const at = await getAccessToken();
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + at, 'Content-Type': contentType },
    body,
  });
  if (!res.ok) throw new Error(`Drive write ${res.status}: ${await res.text()}`);
  return res.json();
}

// Create a subfolder under parentId and return its id.
export async function createFolder(parentId, name) {
  const meta = { name, mimeType: FOLDER_MIME, parents: [parentId] };
  const json = await apiPost(
    `${API}/files?supportsAllDrives=true&fields=id,name`,
    JSON.stringify(meta), 'application/json'
  );
  return json.id;
}

// Find a direct child folder by exact name, or create it. Returns its id.
export async function findOrCreateFolder(parentId, name) {
  const existing = (await listChildren(parentId))
    .find((f) => f.mimeType === FOLDER_MIME && f.name === name);
  return existing ? existing.id : createFolder(parentId, name);
}

// Kopiert eine Datei und konvertiert sie dabei, indem der Ziel-MIME-Type im Body
// gesetzt wird (z.B. .docx → Google Doc: `application/vnd.google-apps.document`).
// Anders als der reine `copyFile` (behält den Quell-MIME) — nötig, weil ein .docx
// von `documents.get` nicht gelesen werden kann. Gibt {id,name,mimeType} zurück.
export async function copyConvert(
  fileId, parentId, name, convertToMime = 'application/vnd.google-apps.document',
) {
  const meta = { name, parents: [parentId], mimeType: convertToMime };
  return apiPost(
    `${API}/files/${fileId}/copy?supportsAllDrives=true&fields=id,name,mimeType`,
    JSON.stringify(meta), 'application/json',
  );
}

// Serverseitige Kopie (gleicher MIME-Typ, volle Aufloesung, nichts wird heruntergeladen).
// appProperties: unsichtbare Schluessel an der Kopie, z. B. { photoKey } fuer Wiederholungslaeufe.
export async function copyFile(fileId, parentId, name, appProperties = undefined) {
  const meta = { name, parents: [parentId], ...(appProperties ? { appProperties } : {}) };
  return apiPost(
    `${API}/files/${fileId}/copy?supportsAllDrives=true&fields=id,name`,
    JSON.stringify(meta), 'application/json',
  );
}

// Binaerdatei (Buffer) in einen Ordner hochladen (multipart). Gibt {id,name} zurueck.
export async function uploadBytes(parentId, name, bytes, mimeType, appProperties = undefined) {
  const boundary = 'access' + '2718281828';
  const meta = { name, parents: [parentId], ...(appProperties ? { appProperties } : {}) };
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`),
    bytes,
    Buffer.from(`\r\n--${boundary}--`),
  ]);
  return apiPost(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id,name',
    body, `multipart/related; boundary=${boundary}`,
  );
}

// Upload a text file into a folder (multipart). Returns the new file id.
// Ersetzt den INHALT einer bestehenden Datei; ID und Name bleiben. Bewusst so und nicht
// "neu hochladen + alte loeschen": zwei gleichnamige Dateien im Zielordner ergaeben
// kurzzeitig einen doppelten Bild-Index, und genau darauf bricht der Abgleich ab. Diesen
// Zwischenzustand gibt es hier gar nicht erst.
export async function replaceFileContent(fileId, bytes, mimeType = 'image/jpeg') {
  const at = await getAccessToken();
  const res = await fetch(
    `https://www.googleapis.com/upload/drive/v3/files/${fileId}?uploadType=media&supportsAllDrives=true&fields=id,name,size`,
    { method: 'PATCH', headers: { Authorization: 'Bearer ' + at, 'Content-Type': mimeType }, body: bytes },
  );
  if (!res.ok) throw new Error(`Drive replace ${res.status}: ${await res.text()}`);
  return res.json();
}

export async function uploadTextFile(parentId, name, content, mimeType = 'application/xml') {
  const boundary = 'access' + '3141592653';
  const meta = { name, parents: [parentId] };
  const body =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n` +
    JSON.stringify(meta) +
    `\r\n--${boundary}\r\nContent-Type: ${mimeType}; charset=UTF-8\r\n\r\n` +
    content +
    `\r\n--${boundary}--`;
  const json = await apiPost(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id,name',
    body, `multipart/related; boundary=${boundary}`
  );
  return json.id;
}

export const DOC_MIME = 'application/vnd.google-apps.document';
export const SHEET_MIME = 'application/vnd.google-apps.spreadsheet';

// Leeres Google Doc (oder mit mimeType = SHEET_MIME: Sheet) direkt im Zielordner anlegen. Create-only.
export async function createGoogleDoc(parentId, name, mimeType = DOC_MIME) {
  const meta = { name, mimeType, parents: [parentId] };
  return apiPost(
    `${API}/files?supportsAllDrives=true&fields=id,name,webViewLink`,
    JSON.stringify(meta), 'application/json',
  );
}

// Hat die Datei/der Ordner schon „jeder mit dem Link = Bearbeiter“? Rein lesend.
export async function hatAnyoneWriter(fileId) {
  const perms = await api(`/files/${fileId}/permissions?supportsAllDrives=true&fields=permissions(type,role)`);
  return (perms.permissions || []).some((p) => p.type === 'anyone' && p.role === 'writer');
}

// Freigabe „jeder mit dem Link = Bearbeiter“ setzen, falls noch nicht vorhanden.
// Bewusst nur für Dateien, die genau dafür gedacht sind (Fragebogen +
// Upload-Ordner, Design-Doc A11): Jeder mit dem Link kann dort ändern und löschen.
// Schranke im Code: nur Objekte, deren Name mit „Upload “
// oder „Questionnaire “ beginnt — so kann kein Aufrufer das interne Archiv öffnen.
// Gibt true zurück, wenn neu gesetzt, false, wenn sie schon bestand.
export async function ensureAnyoneWriter(fileId) {
  const meta = await api(`/files/${fileId}?supportsAllDrives=true&fields=name`);
  if (!/^(Upload |Questionnaire )/.test(meta.name || '')) {
    throw new Error(`Link-Freigabe verweigert: „${meta.name}“ ist weder Upload-Ordner noch Fragebogen`);
  }
  if (await hatAnyoneWriter(fileId)) return false;
  await apiPost(
    `${API}/files/${fileId}/permissions?supportsAllDrives=true`,
    JSON.stringify({ type: 'anyone', role: 'writer', allowFileDiscovery: false }), 'application/json',
  );
  return true;
}

// Alle nicht gelöschten Dateien mit genau diesem Namen (und optional MIME-Typ), über alle sichtbaren Ablagen.
// Für „nie doppelt anlegen“ (z. B. Entwürfe je Name). Paginiert; incompleteSearch → Fehler, damit
// „nichts gefunden“ nie auf einer unvollständigen Suche beruht.
export async function findFilesByName(name, mimeType = null) {
  const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const q = [`name = '${esc(name)}'`, 'trashed = false', mimeType ? `mimeType = '${esc(mimeType)}'` : null].filter(Boolean).join(' and ');
  const out = [];
  let pageToken = '';
  do {
    const p = new URLSearchParams({
      q, corpora: 'allDrives', includeItemsFromAllDrives: 'true', supportsAllDrives: 'true', pageSize: '100',
      fields: 'nextPageToken,incompleteSearch,files(id,name,mimeType,parents,owners(emailAddress),webViewLink)',
    });
    if (pageToken) p.set('pageToken', pageToken);
    const r = await api(`/files?${p}`);
    if (r.incompleteSearch) throw new Error(`Drive-Suche nach „${name}“ unvollständig (incompleteSearch)`);
    out.push(...(r.files || []));
    pageToken = r.nextPageToken || '';
  } while (pageToken);
  return out;
}

// Rollen der Freigaben einer Datei, rein lesend: [{ type, role, emailAddress }].
export async function listPermissions(fileId) {
  const out = [];
  let pageToken = '';
  do {
    const p = new URLSearchParams({ supportsAllDrives: 'true', fields: 'nextPageToken,permissions(id,type,role,emailAddress)' });
    if (pageToken) p.set('pageToken', pageToken);
    const r = await api(`/files/${fileId}/permissions?${p}`);
    out.push(...(r.permissions || []));
    pageToken = r.nextPageToken || '';
  } while (pageToken);
  return out;
}

// Dienstkonto als Bearbeiter freigeben, falls noch nicht (ohne Benachrichtigungsmail). Schranke im Code: nur
// Adressen von Google-Dienstkonten (…iam.gserviceaccount.com), damit über diese Funktion nie eine Person oder
// „jeder mit dem Link“ Zugriff bekommt. Gibt true zurück, wenn neu gesetzt, false, wenn schon Bearbeiter/Inhaber.
export async function ensureServiceAccountWriter(fileId, email) {
  const mail = String(email || '').trim().toLowerCase();
  if (!/^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/.test(mail)) {
    throw new Error(`Freigabe verweigert: „${email}“ ist keine Dienstkonto-Adresse`);
  }
  const perms = await listPermissions(fileId);
  if (perms.some((p) => p.type === 'user' && String(p.emailAddress || '').toLowerCase() === mail && ['writer', 'organizer', 'fileOrganizer', 'owner'].includes(p.role))) return false;
  await apiPost(
    `${API}/files/${fileId}/permissions?supportsAllDrives=true&sendNotificationEmail=false`,
    JSON.stringify({ type: 'user', role: 'writer', emailAddress: mail }), 'application/json',
  );
  return true;
}
