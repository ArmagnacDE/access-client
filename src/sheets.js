// Minimal Google Sheets API v4 client. No external deps.
//
// Replaces the Apps Script `SpreadsheetApp` built-ins used by the two bound
// scripts. Lesen ist der Normalfall; die Schreibpfade (appendRowsAtEnd, updateRow,
// updateCells, replaceTable) sind bewusst wenige und im CLI jeweils an eine explizite
// Aktion gebunden. Was der Mensch im Sheet entscheidet, schreibt das Tool nicht zurueck.

import { getAccessToken } from './google-auth.js';

const API = 'https://sheets.googleapis.com/v4/spreadsheets';

async function api(path) {
  const at = await getAccessToken();
  const res = await fetch(API + path, {
    headers: { Authorization: 'Bearer ' + at },
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(`Sheets API ${res.status}: ${JSON.stringify(json.error || json)}`);
  }
  return json;
}

// List the tab (worksheet) titles of a spreadsheet.
export async function listTabs(spreadsheetId) {
  const json = await api(`/${spreadsheetId}?fields=sheets.properties.title`);
  return (json.sheets || []).map((s) => s.properties.title);
}

// Exact tab lookup — the replacement for the old fuzzy `findSheetByName()`.
// Throws with the available tabs listed, so a typo in the config is obvious.
export async function resolveTab(spreadsheetId, exactTitle) {
  const tabs = await listTabs(spreadsheetId);
  if (tabs.includes(exactTitle)) return exactTitle;
  throw new Error(
    `Tab "${exactTitle}" not found. Available tabs: ${tabs.map((t) => `"${t}"`).join(', ')}`
  );
}

// Read a range as a 2D array of values. `range` is A1 notation, optionally
// prefixed with a tab name, e.g. "Partner!A1:Z200".
//
// valueRenderOption:
//   - FORMATTED_VALUE (default): display strings — right for facts + dates,
//     which we pass through verbatim (locale-formatted, timezone suffix, etc.).
//   - UNFORMATTED_VALUE: raw typed numbers — right for prices, so parsing is not
//     fooled by thousands separators or a currency suffix (review finding).
export async function getValues(spreadsheetId, range, { unformatted = false } = {}) {
  const opt = unformatted ? '?valueRenderOption=UNFORMATTED_VALUE' : '';
  const json = await api(`/${spreadsheetId}/values/${encodeURIComponent(range)}${opt}`);
  return json.values || [];
}

// Mehrere Ranges in EINEM API-Call lesen (Reihenfolge bleibt erhalten). → Array von
// 2D-Value-Arrays, parallel zu `ranges`. Für "je Tab eine Zelle"-Sammelabfragen.
export async function batchGet(spreadsheetId, ranges, { unformatted = false } = {}) {
  if (!ranges.length) return [];
  const qs = ranges.map((r) => `ranges=${encodeURIComponent(r)}`).join('&');
  const opt = unformatted ? '&valueRenderOption=UNFORMATTED_VALUE' : '';
  const json = await api(`/${spreadsheetId}/values:batchGet?${qs}${opt}`);
  return (json.valueRanges || []).map((vr) => vr.values || []);
}

// In einem Partner-Tab markiert eine Zeile mit "Backup:" in Spalte A das Ende der
// aktiven Partner — alles darunter ist Archiv und darf weder Mails noch Orders
// ausloesen. Schneidet vor der Markierung ab (Zeile selbst ebenfalls raus).
// Ohne Markierung bleiben alle Zeilen erhalten.
export function cutAtBackupMarker(rows, colIndex = 0) {
  const idx = rows.findIndex(
    (r) => /^backup:?$/i.test(String((r || [])[colIndex] ?? '').trim())
  );
  return idx === -1 ? rows : rows.slice(0, idx);
}

// Zeilen ans Ende eines Tabs schreiben. Der einzige schreibende Zugriff des Tools —
// im CLI nur mit --write erreichbar.
//
// BEWUSST NICHT values.append: dessen Tabellenerkennung braucht eine gefuellte erste
// Zelle. In einem Tab mit leerer A1, dadurch landete die Zeile in Zeile 1 und schob
// die Kopfzeile nach unten (2026-07-21, repariert). Stattdessen wird die letzte belegte
// Zeile gelesen und mit values.update an eine EXPLIZITE Adresse geschrieben.
// valueInputOption RAW, wenn der Tab reine Daten haelt: USER_ENTERED macht aus
// "2026-01" ein Datum und aus "05" die Zahl 5 — beim Zuruecklesen passen die
// Schluessel dann nicht mehr (E1-Befund 2026-07-29). RAW ist zugleich der
// Injection-Schutz: nichts wird je als Formel interpretiert.
export async function appendRowsAtEnd(spreadsheetId, tab, rows, { lastCol = 'Z', valueInputOption = 'USER_ENTERED' } = {}) {
  if (!rows.length) return { updatedRows: 0 };
  const existing = await getValues(spreadsheetId, `'${tab}'!A1:${lastCol}100000`);
  const firstRow = existing.length + 1;
  const lastRow = firstRow + rows.length - 1;
  const range = `'${tab}'!A${firstRow}:${lastCol}${lastRow}`;

  const at = await getAccessToken();
  const res = await fetch(
    `${API}/${spreadsheetId}/values/${encodeURIComponent(range)}?valueInputOption=${valueInputOption}`,
    {
      method: 'PUT',
      headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
      body: JSON.stringify({ values: rows }),
    }
  );
  if (!res.ok) throw new Error(`Sheets update ${res.status}: ${await res.text()}`);
  return { ...(await res.json()), firstRow };
}

// Eine bestehende Zeile an einer expliziten Position ueberschreiben.
//
// firstCol ist Pflicht, sobald nicht ab A geschrieben wird: values.update fuellt den
// Bereich von links. Neun Werte fuer C..K in einen Bereich ab A wuerden sonst in A..I
// landen und die Formeln in A und B ueberschreiben (Review-Befund).
//
// valueInputOption RAW verhindert, dass Strings wie der Monat "05" als Zahl 5 gelesen
// werden — das wuerde die per Formel gebaute SKU zu "…-526-70" verstuemmeln (Befund 3).
export async function updateRow(
  spreadsheetId, tab, rowNumber, values,
  { firstCol = 'A', lastCol = 'Z', valueInputOption = 'USER_ENTERED' } = {}
) {
  const range = `'${tab}'!${firstCol}${rowNumber}:${lastCol}${rowNumber}`;
  const at = await getAccessToken();
  const res = await fetch(
    `${API}/${spreadsheetId}/values/${encodeURIComponent(range)}?valueInputOption=${valueInputOption}`,
    {
      method: 'PUT',
      headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
      body: JSON.stringify({ values: [values] }),
    }
  );
  if (!res.ok) throw new Error(`Sheets update ${res.status}: ${await res.text()}`);
  return res.json();
}

// Alle Tabs mit Titel und sheetId in EINEM Request (statt listTabs + getSheetIdByTitle je Tab, die bei vielen Tabs
// das Leselimit von 60/min reißen). Reihenfolge wie im Sheet.
export async function listTabsWithIds(spreadsheetId) {
  const json = await api(`/${spreadsheetId}?fields=sheets.properties(sheetId,title)`);
  return (json.sheets || []).map((s) => ({ title: s.properties.title, sheetId: s.properties.sheetId }));
}

// Ganze Tabs über ihre sheetId lesen (values:batchGetByDataFilter, POST): keine Titel in der URL (Längenlimit) und
// keine Verwechslung, wenn ein Titel inzwischen auf einen anderen Tab zeigt. → Map sheetId → 2D-Werte; eine ID, die
// in der Antwort fehlt, fehlt auch in der Map (Aufrufer entscheidet).
export async function batchGetBySheetIds(spreadsheetId, sheetIds, { unformatted = false } = {}) {
  const out = new Map();
  if (!sheetIds.length) return out;
  const at = await getAccessToken();
  const res = await fetch(`${API}/${spreadsheetId}/values:batchGetByDataFilter`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      dataFilters: sheetIds.map((sheetId) => ({ gridRange: { sheetId } })),
      valueRenderOption: unformatted ? 'UNFORMATTED_VALUE' : 'FORMATTED_VALUE',
    }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`Sheets API ${res.status}: ${JSON.stringify(json.error || json)}`);
  for (const vr of json.valueRanges || []) {
    // Die API lässt sheetId 0 weg (Protobuf-Standardwert): ein gridRange ohne sheetId ist Tab 0.
    const ids = (vr.dataFilters || []).filter((f) => f.gridRange).map((f) => f.gridRange.sheetId ?? 0);
    if (ids.length !== 1) throw new Error('batchGetByDataFilter: Antwort ohne eindeutige sheetId');
    out.set(ids[0], vr.valueRange?.values || []);
  }
  return out;
}

// sheetId (numerisch) eines Tabs — noetig fuer batchUpdate-Requests.
export async function getSheetIdByTitle(spreadsheetId, title) {
  const json = await api(`/${spreadsheetId}?fields=sheets.properties(sheetId,title)`);
  const hit = (json.sheets || []).find((s) => s.properties.title === title);
  if (!hit) throw new Error(`Tab "${title}" nicht gefunden.`);
  return hit.properties.sheetId;
}

// batchUpdate (Zeilen einfuegen, Bloecke kopieren). Struktur-Aenderungen laufen NUR
// hierueber, damit Google die Formelbezuege selbst anpasst.
export async function batchUpdate(spreadsheetId, requests) {
  const at = await getAccessToken();
  const res = await fetch(`${API}/${spreadsheetId}:batchUpdate`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests }),
  });
  if (!res.ok) throw new Error(`Sheets batchUpdate ${res.status}: ${await res.text()}`);
  return res.json();
}

// Mehrere Zellbereiche in EINEM Request schreiben. Zellweise Schreibvorgaenge haben beim
// Tab-Umbau das Minutenlimit gerissen (429) — gebuendelt ist es ein Request.
export async function updateCells(spreadsheetId, data, { valueInputOption = 'USER_ENTERED' } = {}) {
  if (!data.length) return { totalUpdatedCells: 0 };
  const at = await getAccessToken();
  const res = await fetch(`${API}/${spreadsheetId}/values:batchUpdate`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ valueInputOption, data }),
  });
  if (!res.ok) throw new Error(`Sheets values:batchUpdate ${res.status}: ${await res.text()}`);
  return res.json();
}

// Formeln (statt berechneter Werte) eines Bereichs lesen.
export async function getFormulas(spreadsheetId, range) {
  const json = await api(`/${spreadsheetId}/values/${encodeURIComponent(range)}?valueRenderOption=FORMULA`);
  return json.values || [];
}

// --- Generierte Tabellen in Tabs schreiben ----------------------------------
// Fuer Reports, die bei jedem Lauf denselben Tab neu befuellen.

// Zeilenschluessel aus den Werten der Schluesselspalten. JSON statt Trennzeichen: ein
// Kunde "Meier; GmbH" und ein Trennzeichen-Join koennten sonst denselben Schluessel
// erzeugen wie ein anderes Spaltenpaar — und der manuelle Vermerk landete an der
// falschen Zeile.
export const rowKey = (values) => (values.every((v) => !v) ? '' : JSON.stringify(values));

/**
 * Fremdtext darf nie als Formel starten: fuehrendes = + - @ wird bei USER_ENTERED
 * von Google als Formel bzw. Zahl interpretiert. Ein Apostroph davor erzwingt Text
 * (gilt auch fuer Report-Tabs).
 * Nur fuer Strings — Zahlen und leere Werte gehen unveraendert durch.
 */
export function guardFormulaText(v) {
  if (typeof v !== 'string') return v;
  return /^[=+\-@]/.test(v) ? "'" + v : v;
}

/** Spaltennummer (1-basiert) -> A1-Buchstabe. 1 -> A, 27 -> AA. */
export function colLetter(n) {
  let s = '';
  for (let x = n; x > 0; x = Math.floor((x - 1) / 26)) s = String.fromCharCode(65 + ((x - 1) % 26)) + s;
  return s;
}

/**
 * Tab-Titel, den Google akzeptiert. Verboten sind : \ / ? * [ ] , Laenge max 100,
 * fuehrende/schliessende Apostrophe. Ein SKU-Titel wie "Danis1985-40-0126-70" bleibt
 * unveraendert; nur exotische Zeichen werden ersetzt.
 */
export function sanitizeTabTitle(title) {
  const clean = String(title ?? '').replace(/[:\\/?*[\]]/g, '-').replace(/^'+|'+$/g, '').trim();
  return (clean || 'Tab').slice(0, 100);
}

/** Legt den Tab an, falls er fehlt. -> { sheetId, created } */
export async function ensureTab(spreadsheetId, title) {
  const json = await api(`/${spreadsheetId}?fields=sheets.properties(sheetId,title)`);
  const hit = (json.sheets || []).find((s) => s.properties.title === title);
  if (hit) return { sheetId: hit.properties.sheetId, created: false };

  const res = await batchUpdate(spreadsheetId, [
    { addSheet: { properties: { title, gridProperties: { frozenRowCount: 1 } } } },
  ]);
  return { sheetId: res.replies[0].addSheet.properties.sheetId, created: true };
}

/**
 * Stellt sicher, dass das Grid eines Tabs mindestens rows × columns fasst.
 * values.update erweitert das Grid NICHT selbst — ein Schreiben jenseits der
 * Grenzen bricht mit "exceeds grid limits" ab. Erweitert wird MONOTON per
 * appendDimension, nie per updateSheetProperties: der Read-modify-write-Weg
 * könnte einen zwischenzeitlich von einem Parallel-Lauf vergrößerten Tab
 * wieder schrumpfen und dabei Zeilen löschen (Review-Befund). Läuft
 * parallel ein zweites appendDimension, wächst der Tab nur etwas mehr.
 */
export async function ensureGrid(spreadsheetId, title, { rows = 0, columns = 0 } = {}) {
  const json = await api(`/${spreadsheetId}?fields=sheets.properties(sheetId,title,gridProperties(rowCount,columnCount))`);
  const hit = (json.sheets || []).find((s) => s.properties.title === title);
  if (!hit) throw new Error(`Tab "${title}" nicht gefunden.`);
  const g = hit.properties.gridProperties || {};
  const sheetId = hit.properties.sheetId;
  const requests = [];
  if (rows > (g.rowCount || 0)) {
    requests.push({ appendDimension: { sheetId, dimension: 'ROWS', length: rows - (g.rowCount || 0) } });
  }
  if (columns > (g.columnCount || 0)) {
    requests.push({ appendDimension: { sheetId, dimension: 'COLUMNS', length: columns - (g.columnCount || 0) } });
  }
  if (!requests.length) return { erweitert: false };
  await batchUpdate(spreadsheetId, requests);
  return { erweitert: true };
}

async function clearRanges(spreadsheetId, ranges) {
  if (!ranges.length) return;
  const at = await getAccessToken();
  const res = await fetch(`${API}/${spreadsheetId}/values:batchClear`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ranges }),
  });
  if (!res.ok) throw new Error(`Sheets batchClear ${res.status}: ${await res.text()}`);
}

/**
 * Trennt generierte von manuellen Spalten. Alles ab der Spalte `Notizen` gehoert dem
 * Menschen — dort stehen Vermerke wie "Ship", "Packed", "warten auf Kunde". Diese
 * Funktion baut den Index Zeilenschluessel -> manuelle Werte aus dem Alt-Bestand.
 *
 * Ohne `Notizen`-Spalte im alten Header gibt es nichts zu retten (erster Lauf oder
 * fremder Tab) — dann lieber leer zurueck als raten, welche Spalte manuell war.
 */
export function extractManualColumns(oldValues, keyColumns, noteHeader = 'Notizen') {
  const out = { headers: [], byKey: new Map(), missingKeyColumns: [], unkeyable: 0, filled: 0 };
  if (!oldValues.length) return out;
  const header = oldValues[0].map((h) => String(h ?? '').trim());
  const start = header.indexOf(noteHeader);
  if (start === -1) return out;

  out.headers = header.slice(start);
  const keyIdx = keyColumns.map((c) => header.indexOf(c));
  out.missingKeyColumns = keyColumns.filter((_, i) => keyIdx[i] === -1);

  for (const row of oldValues.slice(1)) {
    const werte = row.slice(start).map((v) => (v == null ? '' : v));
    if (!werte.some((v) => String(v).trim() !== '')) continue;
    // `filled` zaehlt, was ueberhaupt auf dem Spiel steht. Ohne diese Zahl wuerde der
    // Aufrufer auch dann abbrechen, wenn der Tab gar keine Vermerke enthaelt — und eine
    // reine Spaltenumbenennung waere nur noch von Hand zu ueberstehen.
    out.filled += 1;
    if (out.missingKeyColumns.length) continue;
    const key = rowKey(keyIdx.map((i) => String(row[i] ?? '').trim()));
    // Notiz ohne Schluessel laesst sich nirgends wieder anheften. Zaehlen statt
    // ueberspringen — sonst verschwindet sie beim Aufraeumen, ohne dass es jemand sieht.
    if (!key) { out.unkeyable += 1; continue; }
    out.byKey.set(key, werte);
  }
  return out;
}

/** Baut den neuen Zellblock: generierte Spalten + gerettete manuelle Spalten. */
export function buildTableValues(header, rows, keyColumns, manual, noteHeader = 'Notizen') {
  const keyIdx = keyColumns.map((c) => header.indexOf(c));
  if (keyIdx.some((i) => i === -1)) {
    throw new Error(`Schluesselspalte fehlt im Header: ${keyColumns.join(', ')}`);
  }
  const noteHeaders = manual.headers.length ? manual.headers : [noteHeader];
  const values = [[...header, ...noteHeaders]];
  for (const row of rows) {
    const key = rowKey(keyIdx.map((i) => String(row[i] ?? '').trim()));
    const notes = manual.byKey.get(key) || [];
    const gefuellt = noteHeaders.map((_, i) => notes[i] ?? '');
    values.push([...row, ...gefuellt]);
  }
  return values;
}

/**
 * Ersetzt den Inhalt eines Tabs durch eine generierte Tabelle — und rettet dabei die
 * manuellen Spalten ab `Notizen`, zugeordnet ueber `keyColumns`.
 *
 * Reihenfolge bewusst: erst schreiben, dann den Ueberhang loeschen. Andersherum waere
 * der Tab zwischen Loeschen und Schreiben leer; bricht der Lauf genau dort ab, waeren
 * die manuellen Vermerke weg.
 *
 * @returns { created, rows, preserved, dropped } — `dropped` sind Vermerke, deren Zeile
 *          es nicht mehr gibt (Bestellung versandt o. ae.). Der Aufrufer soll das melden.
 */
export async function replaceTable(
  spreadsheetId, title, header, rows,
  { keyColumns, noteHeader = 'Notizen', dryRun = false } = {}
) {
  const tab = sanitizeTabTitle(title);
  const A1 = `'${tab.replace(/'/g, "''")}'`;

  let oldValues = [];
  let created = false;
  if (dryRun) {
    const tabs = await listTabs(spreadsheetId);
    created = !tabs.includes(tab);
    if (!created) oldValues = await getValues(spreadsheetId, `${A1}!A1:ZZ100000`);
  } else {
    ({ created } = await ensureTab(spreadsheetId, tab));
    if (!created) oldValues = await getValues(spreadsheetId, `${A1}!A1:ZZ100000`);
  }

  const manual = extractManualColumns(oldValues, keyColumns, noteHeader);

  // Der Tab hat eine Notizen-Spalte, aber die Schluesselspalte fehlt: dann laesst sich
  // KEINE Notiz zuordnen, und ein normaler Lauf wuerde sie alle ueberschreiben, ohne
  // etwas zu melden. Passiert schon, wenn jemand eine Titelzeile ueber den Header setzt
  // oder eine Spalte umbenennt. Lieber abbrechen und den Menschen entscheiden lassen.
  if (manual.missingKeyColumns.length && manual.filled) {
    throw new Error(
      `Tab "${tab}": ${manual.filled} manuelle Eintraege stehen ab Spalte "${noteHeader}", aber die ` +
      `Schluesselspalte(n) ` +
      `${manual.missingKeyColumns.map((c) => `"${c}"`).join(', ')} fehlen im Header. ` +
      'Abgebrochen, damit keine manuellen Vermerke verloren gehen. Header im Sheet ' +
      'reparieren (Kopfzeile muss Zeile 1 sein) oder die Notizen sichern und den Tab leeren.'
    );
  }

  const values = buildTableValues(header, rows, keyColumns, manual, noteHeader);

  const neueKeys = new Set(
    rows.map((r) => rowKey(keyColumns.map((c) => String(r[header.indexOf(c)] ?? '').trim())))
  );
  const dropped = [...manual.byKey.keys()].filter((k) => !neueKeys.has(k));
  const preserved = manual.byKey.size - dropped.length;

  const oldRowsCount = oldValues.length;
  const oldColsCount = Math.max(0, ...oldValues.map((r) => r.length));
  const ranges = [];
  if (oldRowsCount > values.length) {
    ranges.push(`${A1}!A${values.length + 1}:${colLetter(Math.max(oldColsCount, values[0].length))}${oldRowsCount}`);
  }
  if (oldColsCount > values[0].length) {
    ranges.push(`${A1}!${colLetter(values[0].length + 1)}1:${colLetter(oldColsCount)}${Math.max(oldRowsCount, values.length)}`);
  }

  const ergebnis = {
    tab, created, rows: rows.length, preserved, dropped,
    unkeyable: manual.unkeyable, clearedRanges: ranges,
  };
  if (dryRun) return { ...ergebnis, written: false };

  const lastCol = colLetter(values[0].length);
  const at = await getAccessToken();
  const res = await fetch(
    `${API}/${spreadsheetId}/values/${encodeURIComponent(`${A1}!A1:${lastCol}${values.length}`)}?valueInputOption=USER_ENTERED`,
    {
      method: 'PUT',
      headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
      body: JSON.stringify({ values }),
    }
  );
  if (!res.ok) throw new Error(`Sheets update ${res.status}: ${await res.text()}`);

  // Ueberhang des vorherigen Laufs wegraeumen: laengere Tabelle von damals, breitere
  // Spalten von damals. Sonst stehen alte Zeilen unter der neuen Tabelle.
  await clearRanges(spreadsheetId, ranges);

  return { ...ergebnis, written: true };
}
