// String-Literale aus JS-Quelltext lesen — für die Meta-Tests, die jedes GraphQL-Dokument im
// Repo prüfen.
//
// Ersetzt die naive Paarung per Regex (`/`([^`]*)`/g` usw.). Die geriet durch einen einzelnen
// Backtick außerhalb eines Strings aus dem Takt, z. B. in einer Regex-Zeichenklasse `/[’`]/`:
// dann galt Code als String und Strings als Code. Fehlalarm, wenn Code wie ein Dokument aussah
// (Vorfall hersteller-links-2026-09/fix.mjs, 07.10.2026), und im schlimmeren Fall fail-open:
// ein echtes Mutations-Dokument wurde gar nicht extrahiert, Form- und Snapshot-Test schwiegen
// (Cross-Review PR #184, Reviewer B3).
//
// Kein JS-Parser, ein Zeichen-Scan mit fünf Zuständen: Code, Kommentar (// und /* */),
// String ('…' und "…"), Template (`…` mit verschachteltem ${…}) und Regex-Literal. Ob ein `/`
// eine Regex beginnt oder dividiert, entscheidet das vorige Token (Standard-Heuristik). Eine
// Regex endet spätestens am Zeilenende: Liegt die Heuristik daneben, ist der Schaden auf eine
// Zeile begrenzt. Was der Lexer trotzdem übersieht, fängt `ungedeckt()` ab (fail-closed).

const REGEX_NACH_WORT = new Set(['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new',
  'delete', 'void', 'throw', 'yield', 'await', 'instanceof']);

/**
 * @param {string} src  JS-Quelltext
 * @returns {{ strings: Array<{ text: string, start: number, end: number }>,
 *             kommentare: Array<{ start: number, end: number }> }}
 *   `text` ist der Inhalt ohne Anführungszeichen. Bei Templates ist es der Rohtext zwischen
 *   den Backticks einschließlich ${…}; verschachtelte Templates darin zählen zum äußeren.
 */
export function literaleAus(src) {
  const strings = [];
  const kommentare = [];
  const istWortZeichen = (c) => /[A-Za-z0-9_$]/.test(c);

  // Liest einen String ab dem öffnenden Anführungszeichen q, gibt den Index NACH dem Ende zurück.
  const leseString = (start, q) => {
    let j = start + 1;
    while (j < src.length && src[j] !== q && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
    return Math.min(j + 1, src.length);
  };

  // Liest ein Template ab dem öffnenden Backtick; ${…} wird als Code gelesen (mit Regex-Heuristik).
  const leseTemplate = (start) => {
    let j = start + 1;
    while (j < src.length) {
      const c = src[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '`') return j + 1;
      if (c === '$' && src[j + 1] === '{') { j = leseCode(j + 2, true); continue; }
      j++;
    }
    return src.length;
  };

  const leseRegex = (start) => {
    let j = start + 1;
    let inKlasse = false;
    while (j < src.length && src[j] !== '\n') {
      const c = src[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '[') inKlasse = true;
      else if (c === ']') inKlasse = false;
      else if (c === '/' && !inKlasse) { j++; while (j < src.length && /[a-z]/i.test(src[j])) j++; return j; }
      j++;
    }
    return j; // Zeilenende: Heuristik lag daneben, Schaden bleibt in dieser Zeile
  };

  // Code lesen — auf oberster Ebene bis zum Dateiende, in ${…} bis zur schließenden Klammer
  // (Rückgabe: Index danach). Strings und Kommentare werden nur oben verbucht; was in ${…}
  // steht, gehört zum Rohtext des umgebenden Templates.
  function leseCode(start, inInterpolation) {
    const verbuche = !inInterpolation;
    let i = start;
    let tiefe = 0;
    let letztes = '';      // letztes signifikantes Zeichen (für die Regex-Heuristik)
    let letztesWort = '';  // letztes Bezeichner-Token, falls `letztes` ein Bezeichnerzeichen ist
    const regexErlaubt = () => {
      if (letztes === '') return true;
      if (istWortZeichen(letztes)) return REGEX_NACH_WORT.has(letztesWort);
      return !(letztes === ')' || letztes === ']');
    };
    while (i < src.length) {
      const c = src[i];
      if (c === '/' && src[i + 1] === '/') {
        const e = src.indexOf('\n', i);
        const end = e === -1 ? src.length : e;
        if (verbuche) kommentare.push({ start: i, end });
        i = end;
      } else if (c === '/' && src[i + 1] === '*') {
        const e = src.indexOf('*/', i + 2);
        const end = e === -1 ? src.length : e + 2;
        if (verbuche) kommentare.push({ start: i, end });
        i = end;
      } else if (c === "'" || c === '"' || c === '`') {
        const end = c === '`' ? leseTemplate(i) : leseString(i, c);
        if (verbuche) strings.push({ text: src.slice(i + 1, end - 1), start: i, end });
        i = end; letztes = c; letztesWort = '';
      } else if (c === '/' && regexErlaubt()) {
        i = leseRegex(i); letztes = '/'; letztesWort = '';
      } else if (istWortZeichen(c)) {
        const anfang = i;
        while (i < src.length && istWortZeichen(src[i])) i++;
        letztesWort = src.slice(anfang, i);
        letztes = src[i - 1];
      } else {
        if (inInterpolation && c === '{') tiefe++;
        if (inInterpolation && c === '}') { if (tiefe === 0) return i + 1; tiefe--; }
        if (!/\s/.test(c)) { letztes = c; letztesWort = ''; }
        i++;
      }
    }
    return src.length;
  }

  let anfang = 0;
  if (src.startsWith('#!')) {
    const e = src.indexOf('\n');
    anfang = e === -1 ? src.length : e;
    kommentare.push({ start: 0, end: anfang });
  }
  leseCode(anfang, false);
  return { strings, kommentare };
}

/**
 * Fail-closed-Netz: Stellen im Rohtext, die wie eine GraphQL-Operation aussehen (`muster`),
 * aber weder in einem erkannten String noch in einem Kommentar liegen. Leer = der Lexer hat
 * alles gesehen. Ein Treffer heißt: der Scanner ist an dieser Stelle blind — oder dort steht
 * echter Code, der so aussieht (dann den Code umformulieren, nicht das Netz lockern).
 * @param {string} src
 * @param {RegExp} muster  ohne g-Flag, z. B. /\bmutation\s*[A-Za-z_]*\s*[({]/
 * @returns {number[]}  Zeilennummern (1-basiert)
 */
export function ungedeckt(src, muster) {
  const { strings, kommentare } = literaleAus(src);
  const bereiche = [...strings, ...kommentare];
  const g = new RegExp(muster.source, `${muster.flags.replace('g', '')}g`);
  const zeilen = [];
  for (const m of src.matchAll(g)) {
    if (!bereiche.some((b) => m.index >= b.start && m.index < b.end)) {
      zeilen.push(src.slice(0, m.index).split('\n').length);
    }
  }
  return zeilen;
}
