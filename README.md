# access-client

Google- und 1Password-Zugänge als ein Paket ohne Fremd-Abhängigkeiten (Node ≥ 22, natives `fetch`), dazu für
Agenten-Sessions der nur lesende Befehl `access-read` und der Entwurfs-Befehl `access-mail` (nie senden).

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
| `access-client/op-read` | `op read`, `op vault get`, `op item get` (Kopf, Einmal-Code), ab v1.6.0 `op vault list` und `op whoami` (nur Namen) an einer geprüften Stelle (ab v1.1.0) |
| `access-client/read` | der Lese-Befehl `access-read` als Funktion `run(argv)` |
| `access-client/security-mail` | Merkmale von Sicherheitsmails (Betreffe, Absender): eine Liste für Gmail-Filter und Wächter (ab v1.3.0) |
| `access-client/gmail-setup` | Sperr-Label und Filter je Postfach anlegen, nur Fehlendes, nie löschen (ab v1.3.0) |
| `access-client/mail-guard` | Mail-Wächter: Filter, Weiterleitungen und Delegierungen gegen den gesicherten Stand, Gesendete mit unbekanntem Client, 2FA-Mails ohne Sperr-Label; nur lesend, dazu der Befehl `mail-guard` (ab v1.4.0) |
| `access-client/mail` | `draftMail`: ein Mail-Entwurf über das delegierte Dienstkonto, auch als Antwort in einen Verlauf; der Kern von `access-mail` (ab v1.3.0) |
| `access-client/read/google` | nur lesende Drive- und Sheets-Aufrufe mit übergebenem Token (nur GET auf feste Pfade), dieselben, die `access-read` nutzt; für Werkzeuge, die ihr Token selbst holen, z. B. OpenClaw-Lesewerkzeuge (ab v1.2.0) |

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
- **Sicherheitsmails auch ohne Label (ab v1.3.0):** Mit `configureGmailGuard({ …, blockSecurityContent: true })`
  schließt jede Suche zusätzlich die Merkmale der zwei Sicherheits-Filter aus (`-subject:(…) -from:(…)`), und Mail,
  Verlauf und Anhang werden vor dem Inhalt an From und Subject geprüft (Prüfabruf `format=metadata`). Grund: Gmail-Filter
  wirken nur auf neue Mails. Die Liste steht einmal in `src/security-mail.js` und speist auch die Filter der
  Einrichtung (`scripts/security-label.mjs`). `access-read`, `access-mail` und openclaw-tools setzen es.
- **Eine Ausnahme:** `readPortalCodeMails` liest Einmal-Codes für Portal-Logins, nur von Absendern aus
  `codeMailSenders` (Pflichtparameter des Aufrufers), nur aus den letzten 20 Minuten.
- **Entwurf mit Profil-Prüfung:** `createCheckedDraft({ token, expectedMailbox, to, subject, html | text, attachments, cc, reply })`
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
  Das Ausgabelimit (`maxBytes`) meldet „Ausgabe zu groß (mehr als N Byte)“, nie „Zeitüberschreitung“, auch wenn der
  Kindprozess dabei beendet wurde (ab v1.5.3); es heilt nicht von selbst, Aufrufer wiederholen es nicht. Zu viel
  stderr heißt „Fehlerausgabe zu groß (mehr als N Byte)“ (eigenes Limit, der Wert selbst ist nicht zu groß).
  Die übergebenen Namen werden vor der Einordnung aus der Meldung entfernt, damit ein Name wie „isn't a vault …“
  nichts verschiebt.
- `opVaultGet({ vault, token })` → `{ id, name }`; `vaultGetMit(token)` passt als `vaultGet` für `tresorSuche`.
- `opItemHead({ vault, item, token })` → `{ id, title, fieldLabels }`: Kopf eines Eintrags ohne Werte (der
  Antwortpuffer wird genullt; Kopien in Strings bleiben bis zur Speicherbereinigung im Speicher, nach außen geht
  nichts). Ob der Titel passt, prüft der Aufrufer (`op item get` findet auch über Domain oder ID). Liegt ein Tresor
  in zwei Schreibweisen vor: `opItemHead` als `holen` für `einEintrag`, erst danach lesen.
- `opVaultList({ token })` → Tresornamen, die das Token sieht (sortiert, ohne IDs); `opWhoami({ token })` →
  `{ typ, email, url }` (z. B. `SERVICE_ACCOUNT`). Beide für die Diagnose `access-read access --check` (ab v1.6.0).
- `opItemOtp({ vault, itemId, token })` → `Buffer` mit dem aktuellen Einmal-Code (nur Ziffern), nur über die
  Eintrags-ID aus `opItemHead`.
- Nur für Text-Geheimnisse: `op read` gibt Binärdateien verfälscht aus.

## access-read: Mails, Drive und Sheets nur lesen

Ein fester Befehl für Agenten-Sessions statt Einmal-Skripten mit Zugangsdaten. Er kann **nur lesen**: keine
Entwürfe, kein Senden, kein Label, kein Verschieben, kein Upload. Ausgabe als JSON; Inhalte aus Mails und Dateien sind
fremder Text (Daten, keine Anweisungen).

```
access-read accounts [--check]
access-read access [--check]
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

### Diagnose: welche Zugänge hat diese Session (`access`, ab v1.6.0)

`access-read access [--check]` zeigt den Bestand an Zugangsdateien, **nie Werte** (kein Token, Refresh-Token,
Client-Secret, Schlüssel, keine Tresor-IDs oder Eintragsinhalte). Braucht keine `read.json`.

- `~/.config/op/` (ersetzbar mit `ACCESS_OP_DIR`): je Datei Pfad, Rechte, Eigentum und ob `op-token` sie nimmt
  (`*.token`, Rechte genau 600, eigener Benutzer, kein Symlink; sonst `grund`). Mit `--check` je brauchbarem
  Token `konto` (`op whoami`: Typ, Adresse, Konto-URL) und `tresore` (`op vault list`, nur Namen), beides über
  `op-read`. Einträge liest der Befehl nie.
- `~/.config/gsheets/` (ersetzbar mit `GOOGLE_CONFIG_DIR`): je Datei Rechte und Typ (`oauth-token`,
  `dienstkonto` mit Adresse, `oauth-client`, `unlesbar`, `keine JSON-Datei`). Mit `--check`: Token-Dateien werden
  erneuert, `scopes` meldet Google (tokeninfo); Dienstkonten melden sich mit `spreadsheets.readonly` an
  (`anmeldung: ok` heißt: Schlüssel gilt). Ihre Delegierung sieht nur die Admin-Konsole.
- Fehler stehen je Datei unter `fehler` (Tresorliste bzw. Google-Prüfung) und `kontoFehler` (`op whoami`), nur als feste
  Meldung (Kategorie oder bekannter OAuth-Code), nie als Text von op oder Google; ein Fehler bricht den Lauf nicht ab.
  Der Befehl endet mit Exit 0, auch wenn Prüfungen scheitern: Die Befunde stehen in der Ausgabe.
- Ein tokenartiger Tresorname erscheint als `[Name nicht ausgegeben]`. Aufgefrischt wird nur gegen Googles
  Token-Endpunkt (fremde `token_uri`: nicht geprüft) und nur, wenn `oauth-client.json` im selben Ordner liegt, den auch
  `google-auth` liest. op-Aufrufe haben hier 15 s Zeitlimit.
- **Gleichzeitig, mit Gesamtzeitlimit (ab v1.7.0):** 1Password und Google laufen gleichzeitig, je Bereich höchstens 8
  Prüfungen auf einmal, `op whoami` und `op vault list` eines Tokens parallel. Nach 30 s (`zeitlimitSekunden` in der
  Ausgabe) endet der Lauf: Was bis dahin nicht fertig ist, hat `fehler: "Gesamtzeitlimit überschritten; nicht fertig
  geprüft"` und keine Teilergebnisse; Google-Aufrufe werden abgebrochen, op-Aufrufe bekommen höchstens die Restzeit.
  Gemessen auf claude (25.11.2026, 11 Tokens, 10 Google-Dateien): vorher 6,6–9,9 s, nachher 1,1 s, gleiche Ausgabe.

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
- `mailDelegation` (ab v1.3.0): `{ "key": "sa-mail.json", "domains": ["example.org"] }`. Mail (Lesen mit `access-read`,
  Entwürfe mit `access-mail`) geht dann für **jedes echte Postfach** der Domains über dieses domänenweit delegierte
  Dienstkonto: Adresse, Kontoname oder Kurzname (`hello` → `hello@<einzige Domain>`). Angefragt wird je Aufruf genau ein
  Scope (`gmail.readonly` zum Lesen, `gmail.compose` für Entwürfe). Ein Konto nur mit `email` (ohne `token`/`delegated`)
  ist dann ein reines Mail-Konto. Drive und Sheets bleiben bei den Konten. Aliase und Gruppen sind keine Postfächer
  (Google meldet `invalid_grant`).
- Lese-Tokens **ohne** `gmail.metadata` erzeugen: Hat ein Token diesen Scope, lehnt Gmail Suche und `format=full` ab.

### Tokens erzeugen (ab v1.5.1)

Ein Konto mit `token` in `read.json` braucht eine OAuth-Token-Datei nur mit Lese-Scopes. `scripts/read-token.mjs`
erzeugt sie in zwei Schritten, weil der Inhaber im eigenen Browser zustimmt und die Sitzung keine Eingabe hat:

```
node scripts/read-token.mjs start --account <name>
node scripts/read-token.mjs finish --account <name> --url-file <datei mit der Weiterleitungs-URL>
```

- `start` zeigt die Anmelde-URL (Desktop-Client aus `oauth-client.json`, PKCE S256, `access_type=offline`,
  `login_hint` = Adresse des Kontos) mit genau `drive.readonly`, `spreadsheets.readonly`, `documents.readonly`,
  `userinfo.email`, `openid`. Zwischenstand (state, Verifier, kein Secret) unter
  `~/.local/state/access-client/read-token-<name>.json`, Rechte 600.
- Nach der Zustimmung landet der Browser auf `http://127.0.0.1:8765/…` („nicht erreichbar“ ist richtig); die ganze
  Adresse aus der Adresszeile geht an `finish`. Der Code darin ist ohne den Verifier dieser Maschine wertlos und verfällt
  nach Minuten.
- `finish` schreibt die Datei aus `read.json` (`token`) unter `~/.config/gsheets/` nur, wenn `state` passt, Google
  genau Lese-Scopes meldet (mindestens Drive und Sheets), ein `refresh_token` kommt und das angemeldete Konto
  (`id_token`) das aus `read.json` ist: neue Datei, Rechte 600, nie überschrieben, nur `refresh_token`, `scope`,
  `token_uri`. Die Ausgabe nennt nie ein Token. Gegenprobe: `access-read accounts --check`.
- Rückweg: nur die Datei löschen. **Nicht** unter myaccount.google.com/permissions den Zugriff der App entziehen: das Lese-Token nutzt denselben OAuth-Client wie `token.json`; ist es dasselbe Google-Konto, wären damit alle Refresh-Tokens dieses Clients ungültig, auch der Haupt-Token (reviewer S137).

### Installieren für Sessions

```
scripts/install-cli.sh v1.3.0
```

legt `~/.local/share/access-client/v1.3.0/` schreibgeschützt aus dem Tag an und setzt `~/.local/bin/access-read` und
`~/.local/bin/access-mail` darauf. Eine Freigaberegel für Sessions nennt dann nur den Befehl `access-read`; was er ausführt, ist ein getaggter
Stand, kein Arbeitsverzeichnis.

## access-mail: Entwürfe, nie senden (ab v1.3.0)

```
access-mail draft --from <postfach> --to <adresse>[,…] --subject <betreff> (--body <text> | --body-file <datei>)
                  [--cc <adresse>[,…]] [--html] [--attach <datei>]…
access-mail draft --from <postfach> --reply-to <mail-id> (--body … | --body-file …) [--to …] [--subject …]
```

- Legt **einen** Entwurf im gewählten Postfach an (über `mailDelegation`, Scope `gmail.compose`), prüft vorher das
  Gmail-Profil. Antwort: Verlauf, `In-Reply-To`/`References`, Empfänger aus `Reply-To` bzw. `From`, Betreff „Re: …“;
  die Ausgangsmail geht durch den Wächter (Sicherheitsmails gesperrt).
- **Senden ist nicht erreichbar:** Es gibt nur `draft`; der einzige Schreibweg ist `createCheckedDraft` → `drafts`
  (`gmailPost` lehnt Versand-Pfade ab). `test/access-mail.test.mjs` probiert Unterbefehle, Optionen und Pfad-Tricks
  durch und hält fest, dass nur `drafts.create` erreicht wird. Entwürfe sind Kommunikationsinhalte: Senden macht ein
  Mensch in Gmail.
- `--body-file` und `--attach` nur aus den `downloadDirs` (aufgelöster Pfad), damit kein Schlüssel und keine Repo-Datei
  in einen Entwurf gerät; Anhänge höchstens 10, zusammen 15 MB. Bei 5xx oder Abbruch kein zweiter Versuch.

## Sperr-Label einrichten: `scripts/security-label.mjs` (ab v1.3.0)

Legt in jedem Postfach das Sperr-Label (`gmailBlockedLabel`) und die Filter aus `src/security-mail.js` an (Betreff auf
mehrere Filter verteilt, ab v1.5.1, dazu ein Absender-Filter) (Aktion
nur „Label anwenden“). Dry-Run ist Standard, `--apply` legt nur Fehlendes an, gelöscht und geändert wird dabei nie (Löschen nur über `--remove-old`, unten); der
Vorher-Stand und die neuen IDs landen in `~/.local/state/access-client/security-label-<zeit>.json`, `--rollback <datei>`
zeigt sie für das Entfernen von Hand. Braucht in der Delegierung zusätzlich `gmail.labels` und `gmail.settings.basic`.
Neues Postfach: `--mailbox <adresse>`.

**Alte Betreff-Filter entfernen (ab v1.5.2):** Jede neue Liste legt neue Filter an, die alten bleiben. `--remove-old
<stand-datei>` (Dry-Run ist Standard, `--apply` löscht) nimmt aus dem Vorher-Stand eines `--apply`-Laufs genau die reinen
Betreff-Sperrfilter früherer Listen (nur `subject:("password reset" …)`, Aktion nur das Sperr-Label, nicht die aktuellen),
löscht nur, wenn sie unverändert im Postfach stehen und alle aktuellen Filter mit demselben Label da sind, und sichert
jeden Filter vorher nach `~/.local/state/access-client/security-label-removed-<zeit>.json` (600). Rückweg:
`--restore <diese-datei> --apply` legt sie wieder an. Löschen ist eine feste Grenze: `--apply` nur mit Freigabe des
Inhabers. Braucht nur `gmail.settings.basic`.

## Mail-Wächter: `mail-guard` (ab v1.4.0)

Prüft je Postfach, was der Generalschlüssel (delegiertes Dienstkonto auf alle Postfächer) anrichten könnte und was die
Filter für Sicherheitsmails übersehen (S114, Sascha 23.11.2026). Gedacht als nächtlicher Job im Container `mail-jobs`
(Shopify `config/mail-jobs.json`); Gmail nur lesend (`gmail.readonly`), einziger Schreibweg ist die ntfy-Meldung.

```
mail-guard check   [--mailbox <adresse>]… [--key <datei>] [--label <name>] [--state-dir <ordner>] [--ntfy-env <VARIABLE>] [--days <n>] [--learn-days <n>] [--dry-run]
mail-guard propose [--mailbox <adresse>]… [--key <datei>] [--label <name>] [--days <n>]
mail-guard accept  --mailbox <adresse> --fingerprint "<abdruck>" [--state-dir <ordner>]
```

1. **Einstellungen** gegen den gesicherten Stand: Filter, Weiterleitungsadressen, automatische Weiterleitung,
   Delegierungen, IMAP, POP (neu/entfernt, einmal gemeldet); dazu jede Nacht, ob Sperr-Label und beide
   Sicherheitsfilter noch da sind. Der Zustand speichert nur Hashes und Kurztexte (Ziel-Domain), keine Kriterien.
   Bei Weiterleitungen meldet er nur, was Mails nach außen bringen kann: eine neue Weiterleitungsadresse, eine
   eingeschaltete oder umgestellte automatische Weiterleitung, einen neuen Filter (ab v1.5.0). Still bleiben
   Entfernen, Ausschalten und ein Statuswechsel einer bekannten Adresse (S123, Board A789 b, A793 a).
   Abwesenheitsnotiz (ab v1.5.0, Board A800 a): Alarm, wenn sie eingeschaltet oder ihr Text geändert wird; gespeichert
   nur ein Hash und der maskierte Betreff. Senden-als und Reply-To: Alarm bei neuer Absender-Adresse oder neuer bzw.
   geänderter Antwortadresse. Dafür gibt es genau eine Leseausnahme zur Versand-Sperre (`readAbsender`: GET fest
   verdrahtet auf die Absender-Liste, Unterpfade und andere Methoden bleiben gesperrt; A800 a).
2. **Gesendete** mit unbekanntem Client-Fingerabdruck (User-Agent/X-Mailer ohne Version, Host der Message-ID, Form der
   MIME-Grenze). Gmail kennzeichnet API-Versand nicht, und das Audit-Log ist mit `gmail.readonly` nicht lesbar; der
   Aufbau der Mail unterscheidet Saschas Clients von einem Skript. Grenze: Nachgebaute Merkmale fallen nicht auf.
   Unbekannte Abdrücke werden nie gelernt, jede solche Mail meldet; ein neuer eigener Client: `mail-guard accept`.
3. **2FA, Codes, Passwort-Links ohne Sperr-Label:** `security-list` = Merkmal der Liste trifft, Filter griff nicht;
   `security` = Kandidat (unbekannter Absender). Gelesen werden nur From und Subject (`format=metadata`), nie der Text.
   Spam und Papierkorb nicht (dort wirken Filter nicht; Phishing mit Sicherheits-Betreff wäre jede Nacht ein Fehlalarm).

- **Erster Lauf** je Postfach legt den Grundstand an (Einstellungen, Abdrücke der Gesendeten der letzten 60 Tage), meldet
  nur Fehlendes beim Sperr-Label und 2FA-Mails der letzten 2 Tage, und listet im Log, was er übernimmt (`gelernt …`, ⚠ bei
  Weiterleitungen, Delegierungen und einteiligen Mails ohne Client). Daran wird die Probe geprüft. Danach je Lauf das
  Fenster seit dem letzten Lauf, in Zeitscheiben (Tag, bei mehr als 1000 Treffern bis zur Stunde halbiert).
- **Meldung** (ntfy, URL aus `--ntfy-env`, Standard `MAIL_GUARD_NTFY_URL`): Postfach, Domain, Datum, Betreff gekürzt
  (32 Zeichen, Ziffernfolgen ab 4 maskiert), höchstens 15 Zeilen; Priorität 4 bei Einstellungen, Gesendeten und
  Filterlücken, 3 bei reinen 2FA-Kandidaten. Ohne Befund keine Meldung.
- **Zustand** in `--state-dir` (Standard `~/.local/state/access-client/mail-guard/`), je Postfach eine Datei mit Rechten
  600, gespeichert erst, wenn die Meldung angekommen ist.
- **Merkmal-Liste ergänzen:** `propose --days 90` zeigt Kandidaten je Domain (Muster, maskierte Betreffe), schreibt
  nichts. Die Liste wird per PR in `src/security-mail.js` erweitert, danach `scripts/security-label.mjs --apply` (nach
  Freigabe); der Wächter ergänzt keine Filter.
- **Nichts geht still verloren:** Das Prüffenster reicht immer bis zum letzten gespeicherten Lauf zurück (nicht gekappt).
  Ein fehlendes Sperr-Label oder ein nicht lesbares Postfach steht als Befund in der Meldung, der Stand dieses Postfachs
  bleibt. Mehr als 1000 Treffer in einer Stunde (Mail-Bombing) meldet er laut; der Rest dieser Stunde bleibt ungeprüft.
  Reihenfolge der Meldung: Einstellungen, Einrichtung, Ausfälle (nie gekürzt), dann Gesendete, Filterlücken, Kandidaten;
  das Log bekommt alle Zeilen.
- **Grenzen:** nachgebaute Client-Merkmale; eine gesendete Mail, die selbst das Sperr-Label trägt (Kopie an sich selbst
  mit Sicherheits-Betreff); Signaturen und Anzeigenamen überwacht er nicht.
- Exit: 0 ok · 1 Meldung nicht zugestellt oder Aufruf falsch (Zustand bleibt) · 3 ein Postfach nicht (vollständig) geprüft.

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
- neu (v1.6.0) `access-read access [--check]` (Diagnose der Zugänge, S110 (Diagnose Konten und Scopes)) und in `op-read` `opVaultList`, `opWhoami`.
- v1.7.0: `access-read access --check` prüft gleichzeitig mit Gesamtzeitlimit 30 s (S146 (access-read access: schneller und Register-Lücken)).
- neu (v1.5.2) `--remove-old`/`--restore` in `scripts/security-label.mjs` (`gmail-filter-cleanup`).
- neu (v1.5.1) `scripts/read-token.mjs` mit `token-setup` (README „Tokens erzeugen“); Merkmal „two-step“ nur noch als
  „two-step authentication“ (S137: „Two-step distillation“ war gesperrt); dazu „two-step verification“, „two-step login“,
  „zweistufige Authentifizierung“, „vérifier votre identité“. Der Betreff steht jetzt auf **mehreren Filtern**
  (`filter-betreff`, `filter-betreff-2`, je unter 1400 Zeichen, `SUBJECT_QUERIES`; neue Phrasen ans Ende, dann ändert
  sich nur der letzte). Achtung: `scripts/security-label.mjs --apply` legt die neuen Filter an; die alten Betreff-Filter
  früherer Versionen entfernt der Inhaber von Hand (das Skript löscht nichts), danach Dry-Run: „vollständig“.
- neu (v1.5.0) Merkmal-Liste um Varianten und Französisch ergänzt (A782 a); To/Cc mit Anzeigenamen nach RFC 2047
  (`encodeAddressHeader`, auch in `buildMime`); Google-Token-Abrufe ohne Weiterleitung (`redirect: 'error'`) mit
  lesbarem Grund (`netzGrund`); Weiterleitungs-Befunde im `mail-guard` wie oben.
- `op-read` (v1.5.3): Ausgabelimit wird vor Zeitüberschreitung geprüft und heißt „Ausgabe zu groß (mehr als N Byte)“ (vorher „Ausgabe größer als N Byte“).
- neu (v1.4.0) `mail-guard` (Modul und Befehl); `gmail-setup` liest zusätzlich Weiterleitungen, Delegierungen, IMAP und POP (`readMailSettings`, nur GET) und exportiert `missingSecurityParts`, `isSecurityFilter`.
- neu (v1.3.0) `mailDelegation`, `access-mail`, `mail` (`draftMail`), `createCheckedDraft` mit `text` und `attachments`
  (`buildDraftMime`), `blockSecurityContent`, `security-mail`, `gmail-setup` mit `scripts/security-label.mjs`.
- neu (v1.2.0) `read/google`: die Lese-Funktionen von `access-read` (`driveQuery`, `driveInfo`, `driveDownload`, `sheetTabs`, `sheetValues`, `idFrom`, `nameQuery`, `folderQuery`) als eigener Export.
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
