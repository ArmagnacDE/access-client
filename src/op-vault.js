// 1Password-Tresore unter zwei Schreibweisen finden: mit und ohne ein Präfix (z. B. während Tresore umbenannt werden).
// Das Präfix gibt der Aufrufer an (`prefix`, z. B. „team-“); ohne Präfix gibt es nur die konfigurierte Schreibweise.
//
// Regeln:
// - Aus einem konfigurierten Namen zwei Kandidaten: wie konfiguriert, dann die andere Schreibweise (mit bzw. ohne
//   Präfix). Je Kandidat genau ein Einzelabruf `op vault get <name>`, nie eine Liste.
// - Auf die andere Schreibweise wird nur ausgewichen, wenn 1Password belegt meldet, dass es den Tresor nicht gibt bzw.
//   der Service Account ihn nicht sieht („… isn't a vault in this account“, Wortlaut von op). Jeder andere Fehler
//   (Token, Netz, Limit) ist ein Stopp.
// - Gibt es beide Schreibweisen, liefert `tresore()` beide; liegt ein Eintrag dann in beiden, ist das ein Stopp wie ein
//   doppelter Eintrag (`einEintrag`).
// - Ergebnis je Lauf im Speicher, je Schreibweise: jede Schreibweise wird höchstens einmal abgefragt (Limit 1.000
//   Lesezugriffe je Stunde und Token).
// - Groß-/Kleinschreibung: `op` findet Tresore unabhängig davon („TEAM-X“ = „team-x“, auch in op://-Verweisen). Deshalb werden die Kandidaten ohne Rücksicht auf Groß-/Kleinschreibung entdoppelt.
// Keine Werte: Hier werden nur Tresornamen und ob ein Eintrag existiert behandelt.

export class OpVaultError extends Error {}

const NICHT_DA = /isn't a vault in this account/i;
// Tresornamen: alles außer Schrägstrich und Steuerzeichen (Teil eines op://-Verweises), höchstens 64 Zeichen.
const NAME_RE = /^[^/\s\u0000-\u001f\u007f-][^/\u0000-\u001f\u007f]{0,63}$/; // nicht mit „-“ oder Leerraum beginnend (sonst Option für op)

/** Belegter Wortlaut: Tresor gibt es nicht bzw. nicht sichtbar. Geprüft wird das ganze stderr (Fehlerobjekt mit
 *  opStderr), nicht nur die erste Zeile: eine vorangestellte Hinweiszeile von op darf nicht zum Stopp führen
 *  */
export const istKeinTresor = (meldung) => NICHT_DA.test(String(meldung ?? ''));
// Fehler aus op-read.js sind schon eingeordnet (opEingeordnet): dort zählt nur `was`, nie der Text (Prozessfehler wie
// eine Zeitüberschreitung bleiben ein Stopp, auch wenn stderr „isn't a vault“ enthält). Text nur für eigene Hüllen.
const keinTresorFehler = (e) => (e?.opEingeordnet ? e.was === 'tresor' : (istKeinTresor(e?.opStderr) || istKeinTresor(e?.message)));

const PREFIX_RE = /^[a-z0-9]{1,16}-$/i;

/** Präfix prüfen: null/leer = keins; sonst Buchstaben/Ziffern mit „-“ am Ende (z. B. „team-“). */
export function pruefePraefix(prefix) {
  if (prefix == null || prefix === '') return null;
  if (typeof prefix !== 'string' || !PREFIX_RE.test(prefix)) throw new OpVaultError('Tresor-Präfix ungültig (Buchstaben/Ziffern, endet auf „-“)');
  return prefix;
}

/** Beide Schreibweisen, die konfigurierte zuerst; ohne Präfix nur die konfigurierte. */
export function schreibweisen(name, { prefix = null } = {}) {
  const n = String(name ?? '');
  if (!NAME_RE.test(n) || n.trim() !== n) throw new OpVaultError(`Tresorname ungültig: ${JSON.stringify(n.slice(0, 40))}`);
  const p = pruefePraefix(prefix);
  if (!p) return [n];
  const andere = n.toLowerCase().startsWith(p.toLowerCase()) ? n.slice(p.length) : `${p}${n}`;
  if (!andere || !NAME_RE.test(andere)) return [n];
  return n.toLowerCase() === andere.toLowerCase() ? [n] : [n, andere];
}

/**
 * Tresor-Suche für einen Lauf.
 * @param {{ vaultGet: (name: string) => Promise<unknown> }} o  vaultGet führt `op vault get <name>` aus und wirft bei
 *   Fehler einen Error mit der ersten Zeile von stderr als message (wie die op-Hüllen der Werkzeuge).
 */
export function tresorSuche({ vaultGet, prefix = null }) {
  const praefix = pruefePraefix(prefix);
  // Je tatsächlichem Kandidatennamen (Kleinbuchstaben) ein Promise<boolean>: „team-x“ und „x“ in einer
  // Konfiguration lösen so zusammen höchstens zwei Abrufe aus, nicht vier.
  const cache = new Map();
  function vorhanden(name) {
    const key = name.toLowerCase();
    if (!cache.has(key)) {
      const p = (async () => {
        try { await vaultGet(name); return true; } catch (e) {
          if (keinTresorFehler(e)) return false;
          throw e;
        }
      })();
      cache.set(key, p);
      p.catch(() => cache.delete(key)); // Stopp-Fehler nicht als Ergebnis merken
    }
    return cache.get(key);
  }
  return {
    /** Vorhandene Schreibweisen (0, 1 oder 2), in Kandidaten-Reihenfolge. Nacheinander abgefragt: Ein Stopp-Fehler beim
     *  ersten Kandidaten verhindert den Abruf des zweiten. */
    async tresore(name) {
      const da = [];
      const kandidaten = schreibweisen(name, { prefix: praefix });
      for (const [i, k] of kandidaten.entries()) {
        try { if (await vorhanden(k)) da.push(k); } catch (e) {
          // Stopp mit klarer Lage: Was gefunden war und welche Abfrage mit unbekannter Meldung scheiterte.
          const lage = i === 0 ? `Abfrage des Tresors „${k}“` : `Gegenprobe auf die andere Schreibweise „${k}“${da.length ? ` (Tresor „${da[0]}“ gefunden)` : ''}`;
          const err = new OpVaultError(`${lage} scheiterte ohne die bekannte Meldung „isn't a vault“ (Netz, Limit, Token oder geänderter Wortlaut von op?): ${String(e?.message ?? e).slice(0, 200)}`);
          Object.defineProperty(err, 'cause', { value: e, enumerable: false });
          throw err;
        }
      }
      return da;
    },
    /** Zahl der bisher gemerkten Kandidatennamen (für Tests). */
    get gemerkt() { return cache.size; },
  };
}

/**
 * Einen Eintrag über alle vorhandenen Schreibweisen eines Tresors suchen.
 * @param {string} name  konfigurierter Tresorname
 * @param {(vault: string) => Promise<T|null>} holen  null = Eintrag fehlt in diesem Tresor; wirft bei anderem Fehler
 * @returns {Promise<{ vault: string, wert: T } | { vault: null, grund: 'kein-tresor' | 'fehlt' }>}
 * @template T
 */
export async function einEintrag(suche, name, holen) {
  const da = await suche.tresore(name);
  if (!da.length) return { vault: null, grund: 'kein-tresor' };
  const treffer = [];
  for (const v of da) {
    const w = await holen(v);
    if (w != null) treffer.push({ vault: v, wert: w });
  }
  if (treffer.length > 1) throw new OpVaultError(`Eintrag in beiden Schreibweisen des Tresors vorhanden (${treffer.map((t) => t.vault).join(', ')}): doppelt, erst bereinigen.`);
  return treffer[0] ?? { vault: null, grund: 'fehlt' };
}

/** op://-Verweis zerlegen: { vault, rest } (rest = „Eintrag/Feld…“). Nur die Form op://<tresor>/<…>. */
export function zerlegeVerweis(ref) {
  const m = /^op:\/\/([^/]+)\/(.+)$/.exec(String(ref ?? ''));
  if (!m) throw new OpVaultError('op-Verweis in unerwarteter Form (erwartet op://<Tresor>/<Eintrag>/<Feld>)');
  return { vault: m[1], rest: m[2] };
}

/** op://-Verweis mit dem tatsächlich gefundenen Tresor. */
export const verweisMit = (ref, vault) => `op://${vault}/${zerlegeVerweis(ref).rest}`;
