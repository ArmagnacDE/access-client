// Generierte Tabellen in Sheet-Tabs schreiben. Der heikle Teil ist nicht das Schreiben,
// sondern das Retten der manuellen Spalten: ein Vermerk wie "Ship" oder "wartet auf
// Kunde", der nach dem Lauf an der falschen Zeile klebt, ist schlimmer als keiner.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildTableValues, colLetter, extractManualColumns, rowKey, sanitizeTabTitle,
} from '../src/sheets.js';

const HEADER = ['Bestellung', 'Kunde', 'Alter_Tage'];
const ROWS = [
  ['B1', 'Anna', 10],
  ['B2', 'Bert', 20],
];

test('colLetter rechnet ueber Z hinaus', () => {
  assert.equal(colLetter(1), 'A');
  assert.equal(colLetter(26), 'Z');
  assert.equal(colLetter(27), 'AA');
  assert.equal(colLetter(52), 'AZ');
  assert.equal(colLetter(53), 'BA');
  assert.equal(colLetter(702), 'ZZ');
});

test('sanitizeTabTitle laesst normale SKUs unveraendert', () => {
  assert.equal(sanitizeTabTitle('Danis1985-40-0126-70'), 'Danis1985-40-0126-70');
  assert.equal(sanitizeTabTitle('Haus-Séailles2001-70-0925-70'), 'Haus-Séailles2001-70-0925-70');
});

test('sanitizeTabTitle entfernt, was Google im Tab-Namen verbietet', () => {
  assert.equal(sanitizeTabTitle('A/B:C*D?E[F]G\\H'), 'A-B-C-D-E-F-G-H');
  assert.equal(sanitizeTabTitle("'quoted'"), 'quoted');
  assert.equal(sanitizeTabTitle('x'.repeat(150)).length, 100);
  assert.equal(sanitizeTabTitle(''), 'Tab');
  assert.equal(sanitizeTabTitle(null), 'Tab');
});

test('rowKey unterscheidet Spaltengrenzen', () => {
  // Mit einem Trennzeichen-Join waeren beide "a b" — der Vermerk landete an der
  // falschen Zeile. JSON haelt die Grenze.
  assert.notEqual(rowKey(['a', 'b']), rowKey(['a b', '']));
  assert.equal(rowKey(['', '']), '', 'leere Schluessel zaehlen nicht');
});

test('erster Lauf: kein Alt-Bestand, Notizen-Spalte wird angelegt', () => {
  const manual = extractManualColumns([], ['Bestellung']);
  assert.deepEqual(manual.headers, []);
  const values = buildTableValues(HEADER, ROWS, ['Bestellung'], manual);
  assert.deepEqual(values[0], ['Bestellung', 'Kunde', 'Alter_Tage', 'Notizen']);
  assert.deepEqual(values[1], ['B1', 'Anna', 10, '']);
});

test('manuelle Notiz folgt ihrer Bestellung, auch wenn die Zeile umsortiert wurde', () => {
  const alt = [
    ['Bestellung', 'Kunde', 'Alter_Tage', 'Notizen'],
    ['B2', 'Bert', 19, 'Ship'],
    ['B1', 'Anna', 9, 'wartet auf Kunde'],
  ];
  const manual = extractManualColumns(alt, ['Bestellung']);
  const values = buildTableValues(HEADER, ROWS, ['Bestellung'], manual);
  assert.deepEqual(values[1], ['B1', 'Anna', 10, 'wartet auf Kunde']);
  assert.deepEqual(values[2], ['B2', 'Bert', 20, 'Ship']);
});

test('mehrere manuelle Spalten bleiben in ihrer Reihenfolge', () => {
  const alt = [
    ['Bestellung', 'Kunde', 'Alter_Tage', 'Notizen', 'Status', 'Wer'],
    ['B1', 'Anna', 9, 'Karton XL', 'gepackt', 'Anna'],
  ];
  const manual = extractManualColumns(alt, ['Bestellung']);
  assert.deepEqual(manual.headers, ['Notizen', 'Status', 'Wer']);
  const values = buildTableValues(HEADER, ROWS, ['Bestellung'], manual);
  assert.deepEqual(values[0], ['Bestellung', 'Kunde', 'Alter_Tage', 'Notizen', 'Status', 'Wer']);
  assert.deepEqual(values[1], ['B1', 'Anna', 10, 'Karton XL', 'gepackt', 'Anna']);
  assert.deepEqual(values[2], ['B2', 'Bert', 20, '', '', ''], 'neue Zeile bekommt leere Notizspalten');
});

test('neue generierte Spalte schiebt die Notizen nach rechts, ohne sie zu verlieren', () => {
  const alt = [
    ['Bestellung', 'Kunde', 'Notizen'],
    ['B1', 'Anna', 'Ship'],
  ];
  const manual = extractManualColumns(alt, ['Bestellung']);
  const values = buildTableValues(HEADER, ROWS, ['Bestellung'], manual); // HEADER hat Alter_Tage zusaetzlich
  assert.deepEqual(values[0], ['Bestellung', 'Kunde', 'Alter_Tage', 'Notizen']);
  assert.deepEqual(values[1], ['B1', 'Anna', 10, 'Ship']);
});

test('ohne Notizen-Spalte im Alt-Header wird nichts geraten', () => {
  const alt = [
    ['Bestellung', 'Kunde', 'Irgendwas'],
    ['B1', 'Anna', 'Ship'],
  ];
  const manual = extractManualColumns(alt, ['Bestellung']);
  assert.deepEqual(manual.headers, []);
  assert.equal(manual.byKey.size, 0, 'lieber nichts retten als die falsche Spalte');
  assert.deepEqual(manual.missingKeyColumns, [], 'ohne Notizen gibt es nichts zu verlieren');
});

// Frueher lief der Lauf hier stumm weiter und ueberschrieb alle Notizen mit Leerstring.
// Realistischer Ausloeser: jemand setzt eine Titelzeile ueber den Header, oder benennt
// "Bestellung" um — dann ist Zeile 1 nicht mehr der Header.
test('fehlende Schluesselspalte bei vorhandenen Notizen wird gemeldet, nicht verschluckt', () => {
  const alt = [
    ['Kunde', 'Notizen'],
    ['Anna', 'Ship'],
  ];
  const manual = extractManualColumns(alt, ['Bestellung']);
  assert.deepEqual(manual.missingKeyColumns, ['Bestellung']);
  assert.equal(manual.filled, 1, 'ein Vermerk steht auf dem Spiel — der Aufrufer bricht ab');
  assert.equal(manual.byKey.size, 0);
  assert.deepEqual(manual.headers, ['Notizen'], 'Spaltenbreite bleibt bekannt');
});

// Sonst waere jede Umbenennung einer Schluesselspalte nur noch von Hand zu ueberstehen,
// auch wenn im Tab gar nichts Handgeschriebenes steht.
test('fehlende Schluesselspalte OHNE Notizen ist kein Abbruchgrund', () => {
  const alt = [
    ['Kunde', 'Notizen'],
    ['Anna', ''],
  ];
  const manual = extractManualColumns(alt, ['Kunden_ID']);
  assert.deepEqual(manual.missingKeyColumns, ['Kunden_ID']);
  assert.equal(manual.filled, 0, 'nichts zu verlieren, also kein Abbruch');
});

test('Notiz in einer Zeile ohne Schluesselwert wird gezaehlt, nicht stillschweigend fallengelassen', () => {
  const alt = [
    ['Bestellung', 'Kunde', 'Notizen'],
    ['', '', 'freie Notiz irgendwo'],
    ['B1', 'Anna', 'Ship'],
  ];
  const manual = extractManualColumns(alt, ['Bestellung']);
  assert.equal(manual.unkeyable, 1);
  assert.equal(manual.byKey.size, 1);
});

test('leere Notizzeilen werden nicht mitgeschleppt und nicht als Verlust gezaehlt', () => {
  const alt = [
    ['Bestellung', 'Kunde', 'Notizen'],
    ['B1', 'Anna', ''],
    ['B2', 'Bert', '   '],
    ['', '', ''],
  ];
  const manual = extractManualColumns(alt, ['Bestellung']);
  assert.equal(manual.byKey.size, 0);
  assert.equal(manual.unkeyable, 0, 'eine leere Zeile ist kein verlorener Vermerk');
});

test('zusammengesetzter Schluessel: Kunde + Email', () => {
  const header = ['Kunde', 'Email', 'Anzahl'];
  const rows = [['M. Mueller', 'a@x.de', 2], ['M. Mueller', 'b@x.de', 1]];
  const alt = [
    ['Kunde', 'Email', 'Anzahl', 'Notizen'],
    ['M. Mueller', 'b@x.de', 1, 'der zweite Mueller'],
  ];
  const manual = extractManualColumns(alt, ['Kunde', 'Email']);
  const values = buildTableValues(header, rows, ['Kunde', 'Email'], manual);
  assert.deepEqual(values[1], ['M. Mueller', 'a@x.de', 2, ''], 'Namensvetter bekommt die Notiz NICHT');
  assert.deepEqual(values[2], ['M. Mueller', 'b@x.de', 1, 'der zweite Mueller']);
});

test('fehlende Schluesselspalte im neuen Header ist ein Fehler, kein stiller Verlust', () => {
  assert.throws(
    () => buildTableValues(HEADER, ROWS, ['GibtsNicht'], { headers: [], byKey: new Map() }),
    /Schluesselspalte fehlt/
  );
});

test('leere Zeilenliste liefert nur den Header', () => {
  const values = buildTableValues(HEADER, [], ['Bestellung'], { headers: [], byKey: new Map() });
  assert.equal(values.length, 1);
});
