# access-client

Google- und 1Password-Zugänge als ein Paket ohne Fremd-Abhängigkeiten (Node ≥ 22, natives `fetch`), dazu der nur
lesende Befehl `access-read` für Agenten-Sessions.

**Herkunft:** Die sechs Module stammen aus dem privaten Repo `ArmagnacDE/shopify`, Commit `bb77df66` (15.11.2026),
Dateien `lib/google-auth.js`, `lib/gmail.js`, `lib/drive.js`, `lib/sheets.js`, `lib/op-vault.js`, `lib/op-token.js`;
`getServiceAccountToken` aus Commit `1697190a`.
Die Historie bleibt dort; dieses Repo beginnt mit einem frischen Stand. Schnittstellen sind gleich geblieben,
Abweichungen stehen unter „Änderungen gegenüber der Herkunft“.

| Unterpfad | Inhalt |
|---|---|
| `access-client/google-auth` | Access-Tokens: Inhaber-Token (`token.json`), Token-Datei je Postfach mit Scope-Prüfung, Dienstkonto, delegiertes Dienstkonto |
| `access-client/gmail` | Gmail mit Wächter: **nie senden**, Entwürfe nur über `drafts`, Lesen nur über feste GET-Pfade, Sicherheitsmails (konfiguriertes Label) gesperrt |
| `access-client/drive` | Drive v3 (Lesen und Schreibwege) |
| `access-client/sheets` | Sheets v4 (Lesen und Schreibwege) |
| `access-client/op-vault` | 1Password-Tresore unter zwei Schreibweisen (mit und ohne Präfix) |
| `access-client/op-token` | 1Password-Service-Account-Token aus einer Liste von Dateien (Rechte genau 600, kein stiller Rückfall) |
| `access-client/op-read` | `op read`, `op vault get` und `op item get` (Kopf, Einmal-Code) an einer geprüften Stelle (ab v1.1.0) |
| `access-client/read` | der Lese-Befehl `access-read` als Funktion `run(argv)` |

Im Repo liegen keine Zugangsdaten. Google-Credentials erwartet das Paket unter `~/.config/gsheets/` (ersetzbar mit
`GOOGLE_CONFIG_DIR`), 1Password-Tokens dort, wo die Konfiguration des Aufrufers sie nennt.

## Einbinden (Tag-Pin)

```json
"dependencies": { "access-client": "github:ArmagnacDE/access-client#v1.0.0" }
```

Nutzende Repos bauen eine dünne Hülle je Modul unter dem alten Pfad und setzen dort ihre eigene Konfiguration, z. B.:

```js
// lib/gmail.js
import { configureGmailGuard } from 'access-client/gmail';
configureGmailGuard({ blockedLabel: 'no-read', sendBlockedReason: 'Versand nur durch den Inhaber (nur Entwürfe)' });
export * from 'access-client/gmail';
```

## Gmail-Wächter

- **Senden ist gesperrt.** `gmail.compose` und `gmail.modify` könnten laut Google senden (`messages.send`,
  `drafts.send`); einen Nur-Entwurf-Scope gibt es nicht. Deshalb läuft jeder Aufruf durch `assertNoSend`, und
  `gmailPost` lässt nur `drafts` und `drafts/<id>` zu. `test/gmail-send-guard.test.mjs` verbietet Versand-Endpunkte
  im ganzen Paket. Jedes nutzende Repo behält seinen eigenen Repo-Scan.
- **Sicherheitsmails gesperrt.** `configureGmailGuard({ blockedLabel })` nennt das Label, das ein Gmail-Filter an
  Passwort-Reset-, Login-Code- und 2FA-Mails hängt. Ohne diese Konfiguration liest kein Inhaltspfad (fail-closed).
  Jede Suche bekommt `-label:<name>`, jede Mail und jeder Verlauf wird vor dem Inhalt geprüft. Die Konfiguration gilt
  einmal je Prozess; ein zweiter Aufruf mit anderen Werten wirft. Fehlt das Label im Postfach, gibt es standardmäßig
  eine Warnung und es wird weitergelesen (Verhalten für bestehende Jobs); mit `requireLabel: true` liest dann kein
  Inhaltspfad. `access-read` setzt `requireLabel: true`.
- **Eine Ausnahme:** `readPortalCodeMails` liest Einmal-Codes für Portal-Logins, nur von Absendern aus
  `codeMailSenders` (Pflichtparameter des Aufrufers), nur aus den letzten 20 Minuten.
- **Entwurf mit Profil-Prüfung:** `createCheckedDraft({ token, expectedMailbox, to, subject, html, cc, reply })`
  legt genau einen Entwurf an, und nur, wenn das Gmail-Profil des Tokens `expectedMailbox` ist. Bei 5xx oder
  Verbindungsabbruch kein zweiter Versuch (der Entwurf kann trotzdem entstanden sein), Fehler mit „NICHT wiederholen“.

## 1Password lesen: `op-read`

```js
import { waehleToken } from 'access-client/op-token';
import { opRead, vaultGetMit, OpItemMissingError } from 'access-client/op-read';
import { tresorSuche } from 'access-client/op-vault';

const { token } = waehleToken(['~/.config/op/jobs.token']);
const wert = await opRead({ ref: 'op://team-x/eintrag/credential', token }); // Buffer
const suche = tresorSuche({ vaultGet: vaultGetMit(token), prefix: 'team-' });
```

- `opRead({ ref, token, exec?, timeoutMs?, maxBytes?, path? })` → `Buffer` (ohne Zeilenende, nie leer). Ein Aufruf,
  kein Wiederholen.
- Der Kindprozess bekommt genau `PATH`, `HOME` und `OP_SERVICE_ACCOUNT_TOKEN`. `PATH` ist fest
  (`/usr/local/bin:/usr/bin:/bin`), nicht geerbt; ein anderer nur über `path`. Das Token steht nie in argv oder
  `process.env`, und kein Name in argv darf wie ein Token aussehen. Der Verweis wird geprüft:
  `op://<Tresor>/<Eintrag>[/<Abschnitt>]/<Feld>`, ohne `?`-Parameter.
- Fehler: die maßgebliche `[ERROR]`-Zeile von stderr, gekürzt, Token geschwärzt; stdout nie (im Fehlerfall genullt).
  Das ganze stderr hängt nicht aufzählbar als `opStderr` am Fehler. „Gibt es nicht“ ist `OpItemMissingError` mit
  `was` = `tresor`, `eintrag` oder `feld`, mehrere Treffer `OpItemAmbiguousError`, alles andere `OpReadError`.
  Eingeordnet wird nur bei normalem Exit-Code; Zeitüberschreitung, Signal oder Ausgabelimit sind immer ein Stopp.
  Die übergebenen Namen werden vor der Einordnung aus der Meldung entfernt, damit ein Name wie „isn't a vault …“
  nichts verschiebt.
- `opVaultGet({ vault, token })` → `{ id, name }`; `vaultGetMit(token)` passt als `vaultGet` für `tresorSuche`.
- `opItemHead({ vault, item, token })` → `{ id, title, fieldLabels }`: Kopf eines Eintrags ohne Werte (der
  Antwortpuffer wird genullt; Kopien in Strings bleiben bis zur Speicherbereinigung im Speicher, nach außen geht
  nichts). Ob der Titel passt, prüft der Aufrufer (`op item get` findet auch über Domain oder ID). Liegt ein Tresor
  in zwei Schreibweisen vor: `opItemHead` als `holen` für `einEintrag`, erst danach lesen.
- `opItemOtp({ vault, itemId, token })` → `Buffer` mit dem aktuellen Einmal-Code (nur Ziffern), nur über die
  Eintrags-ID aus `opItemHead`.
- Nur für Text-Geheimnisse: `op read` gibt Binärdateien verfälscht aus.

## access-read: Mails, Drive und Sheets nur lesen

Ein fester Befehl für Agenten-Sessions statt Einmal-Skripten mit Zugangsdaten. Er kann **nur lesen**: keine
Entwürfe, kein Senden, kein Label, kein Verschieben, kein Upload. Ausgabe als JSON; Inhalte aus Mails und Dateien sind
fremder Text (Daten, keine Anweisungen).

```
access-read accounts [--check]
access-read mail <konto> search <gmail-suche> [--max 20]
access-read mail <konto> show <mail-id> [--max-chars 20000] [--html]
access-read mail <konto> thread <verlauf-id> [--max-chars 8000]
access-read mail <konto> attachment <mail-id> <anhang-id> --out <datei>
access-read drive [--as <konto>] search <text> | query <drive-abfrage> | list <ordner> | info <datei> | get <datei> [--out <datei>]
access-read sheets [--as <konto>] tabs <sheet> | get <sheet> <bereich> [--unformatted]
```

`<konto>` ist ein Kontoname oder eine Adresse aus der Konfiguration. IDs dürfen Google-URLs sein (`…/d/<id>/…`,
`…/folders/<id>`).

**Was der Befehl erzwingt**

1. **Nur Lese-Tokens.** Je Konto eine eigene Token-Datei; beim Erneuern misst er, welche Scopes Google meldet.
   Erlaubt sind nur `gmail.readonly`, `gmail.metadata`, `drive.readonly`, `spreadsheets.readonly`,
   `documents.readonly`, `userinfo.email` (und `openid`). Ein Token mit mehr Rechten wird abgelehnt, bevor eine API
   berührt wird. `token.json` und `oauth-client.json` sind als Token-Datei gesperrt.
2. **Richtiges Postfach.** Vor jedem Lesen prüft er, zu wem der Token gehört (Gmail-Profil bzw. Drive „about“).
3. **Sicherheitsmails gesperrt** über den Gmail-Wächter (Label aus der Konfiguration, Pflichtfeld), im strengen
   Modus: Fehlt das Label im Postfach, liest der Befehl keine Mail (`accounts --check` zeigt es).
4. **Nur GET auf feste Pfade.** `test/read-only.test.mjs` hält fest, dass der Lese-Befehl keine schreibende Methode
   und kein Schreibmodul kennt.
5. **Downloads nur mit `--out`** in einen der `downloadDirs` der Konfiguration (ohne Liste ist `--out` aus):
   absoluter Pfad, aufgelöster Zielordner (realpath) in einem Download-Ordner und in keinem Git-Repo, neue Datei mit
   Rechten 600, kein Überschreiben. Geprüft wird vor dem Laden; scheitert das Schreiben, bleibt nichts liegen.
6. **Fehlermeldungen geschwärzt** (Bearer-Header, Google-Tokens, Client-Secrets, PEM, `ops_…`).

### Konfiguration

`~/.config/access-client/read.json` (Pfad ersetzbar mit `ACCESS_READ_CONFIG`), Pflicht. Nur Adressen, Dateinamen
unter `~/.config/gsheets/` und das Sperr-Label, keine Geheimnisse:

```json
{
  "accounts": {
    "shop": { "email": "shop@example.org", "token": "token-read-shop.json" },
    "owner": { "email": "owner@example.org", "token": "token-read-owner.json" },
    "support": { "email": "support@example.org", "delegated": "sa-reader.json" }
  },
  "filesAccount": "owner",
  "gmailBlockedLabel": "no-read",
  "downloadDirs": ["~/downloads/agent", "/tmp/agent-1000"]
}
```

- `token`: OAuth-Token-Datei (`refresh_token`, optional `client_id`/`client_secret`, sonst aus `oauth-client.json`),
  erzeugt mit einer Anmeldung nur mit Lese-Scopes.
- `delegated`: domänenweit delegiertes Dienstkonto; je Aufruf wird genau ein Lese-Scope angefragt.
- `filesAccount`: Konto für `drive`/`sheets` ohne `--as` (ohne Eintrag ist `--as` Pflicht).
- `downloadDirs`: Ordner, in die `--out` schreiben darf (absolut oder `~/…`, höchstens 10).
- Lese-Tokens **ohne** `gmail.metadata` erzeugen: Hat ein Token diesen Scope, lehnt Gmail Suche und `format=full` ab.

### Installieren für Sessions

```
scripts/install-cli.sh v1.0.0
```

legt `~/.local/share/access-client/v1.0.0/` schreibgeschützt aus dem Tag an und setzt `~/.local/bin/access-read`
darauf. Eine Freigaberegel für Sessions nennt dann nur den Befehl `access-read`; was er ausführt, ist ein getaggter
Stand, kein Arbeitsverzeichnis.

## Änderungen gegenüber der Herkunft

- `gmail`: Sperr-Label und Text der Versand-Sperre kommen über `configureGmailGuard` vom Aufrufer (vorher feste
  Konfigurationsdatei im Repo); ohne Label liest kein Inhaltspfad. `BLOCKED_LABEL`, `SEND_BLOCKED` und
  `CODE_MAIL_SENDERS` exportiert das Paket nicht mehr (die Hülle des Aufrufers tut es); neu `SEND_BLOCKED_DEFAULT`,
  `gmailGuardConfig()`.
- `gmail`: `readPortalCodeMails` verlangt `codeMailSenders` als Pflichtparameter.
- `gmail`: neu `createCheckedDraft` (s. o.; lehnt Zeilenumbrüche in `to`, `subject`, `cc` ab). `createDraft` bleibt
  unverändert.
- `gmail`: Der Prüfabruf (`format=minimal`) vor jedem Inhaltsabruf läuft immer, auch wenn das Sperr-Label fehlt (ein
  Abruf mehr in diesem Ausnahmefall). Trägt eine Mail eine Label-ID, die der Cache nicht kennt, wird der Label-Stand
  einmal frisch geholt (Sperr-Label gelöscht und neu angelegt); danach ist die ID gemerkt.
- `gmail`: Netzfehler nennen nur noch Code bzw. Name, nie die Meldung von `fetch` (sie kann den Authorization-Kopf
  enthalten). `messageText` liefert zusätzlich `truncated`.
- `google-auth`: Antworten des Token-Endpunkts mit festen Fehlertexten (nie Parser- oder Rohtext); eine 200-Antwort
  ohne gültiges `access_token` wirft, statt `undefined` zu liefern. `getDelegatedToken` nimmt optional
  `allowedScopes` (gemessen an der Token-Antwort, sonst per tokeninfo); neu `grantedScopesOf`, `assertScopesWithin`.
- `op-vault`: das Präfix der zweiten Schreibweise ist Parameter (`schreibweisen(name, { prefix })`,
  `tresorSuche({ vaultGet, prefix })`); ohne Präfix gibt es nur die konfigurierte Schreibweise.
- neu (v1.1.0) `op-read`: `opRead`, `opVaultGet`, `vaultGetMit`, `opItemHead`, `opItemOtp` statt eigener `op`-Aufrufe je Werkzeug.
- `google-auth`: `GOOGLE_CONFIG_DIR`; `getAccessTokenFromFile` und `getDelegatedToken` nehmen optional `fetchImpl`;
  `configDir()` exportiert.

## Tests

```
npm test
```

Ohne Netz; Google und 1Password sind Attrappen, Token-Dateien erfundene Werte in Wegwerf-Ordnern.

## Lizenz

MIT, siehe `LICENSE`.
