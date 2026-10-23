# ModSecurity 2.9.15 — Installation auf dem Windows-Server

Zielsystem: Apache Lounge 2.4.62 Win64 VS17, PHP 5.3.29 (mod_php), Joomla.
Das Modul wurde als x64 mit Visual Studio 2022 (VS17) gebaut — binär passend
zur Apache-Lounge-VS17-Serie. PCRE2 und libxml2 sind statisch eingebunden,
es werden keine zusätzlichen DLLs benötigt.

## 1. Dateien aus dem Build-Artefakt

| Datei | Ziel auf dem Server |
|---|---|
| `mod_security2.so` | `D:\Apache24\modules\` |
| `modsecurity.conf-recommended` | `D:\Apache24\conf\modsecurity.conf` (umbenennen) |
| `unicode.mapping` | `D:\Apache24\conf\` |
| `legacy-php-guard.conf` | `D:\Apache24\conf\` |

## 2. `modsecurity.conf` anpassen (Windows-Pfade)

Die recommended-Konfiguration enthält Unix-Pfade. Ändern:

```apache
SecTmpDir  "D:/Apache24/logs/"
SecDataDir "D:/Apache24/logs/"
SecAuditLog "D:/Apache24/logs/modsec_audit.log"
```

`SecUnicodeMapFile unicode.mapping 20127` unverändert lassen — der Pfad ist
relativ zur `modsecurity.conf`, und `unicode.mapping` liegt daneben in `conf\`.

`SecRuleEngine DetectionOnly` ist dort bereits Default — so lassen für den Rollout.

## 3. `httpd.conf` erweitern

```apache
# ModSecurity benötigt mod_unique_id
LoadModule unique_id_module modules/mod_unique_id.so
LoadModule security2_module modules/mod_security2.so

<IfModule security2_module>
    Include conf/modsecurity.conf
    Include conf/legacy-php-guard.conf
</IfModule>
```

Reihenfolge wichtig: `modsecurity.conf` vor `legacy-php-guard.conf`.

## 4. Konfiguration testen und neu starten

```cmd
D:\Apache24\bin\httpd.exe -t
D:\Apache24\bin\httpd.exe -k restart
```

`httpd -t` muss `Syntax OK` melden. Falls das Modul nicht lädt
("Cannot load ... into server"): Windows-Ereignisanzeige bzw. `error.log`
prüfen; VC++-2022-Redistributable (x64) muss vorhanden sein — ist es,
da Apache Lounge VS17 bereits läuft.

## 5. Rollout-Phase: DetectionOnly

Mindestens einige Tage mit `SecRuleEngine DetectionOnly` laufen lassen und
normale Nutzung testen:

- Login (Frontend + Joomla-Administration)
- Formulare, Kontaktformulare
- Datei-/Bild-Uploads (Medienmanager)
- Erweiterungsinstallation
- eventuelle API-Aufrufe

Danach `D:\Apache24\logs\error.log` und `modsec_audit.log` auf Meldungen mit
`id "11000xx"` prüfen. Jede Meldung bei legitimer Nutzung = False Positive →
Limit in `legacy-php-guard.conf` anheben (z.B. `&ARGS_POST @gt 150`, wenn
Joomla-Formulare mehr Felder senden).

## 6. Blocking aktivieren

Erst wenn keine legitimen Requests mehr anschlagen, in `modsecurity.conf`:

```apache
SecRuleEngine On
```

Dann `httpd -k restart`.

## 7. Funktionstest nach Aktivierung

Von einem Client (ersetze `server` durch den Hostnamen):

```cmd
:: muss 400 liefern (zu viele Argumente)
curl -s -o NUL -w "%%{http_code}" "http://server/?a1=1&a2=1& ... 350 Parameter"

:: muss 400 liefern (doppelter Multipart-Header), Testdatei siehe test\smoke.ps1
```

Die CI führt dieselben Tests automatisch gegen jedes gebaute Artefakt aus
(`test/smoke.ps1`) — ein hochgeladenes Artefakt hat diese Tests bereits bestanden.

## 8. Rollback

In `httpd.conf` die beiden `LoadModule`-/`Include`-Zeilen auskommentieren,
`httpd -k restart`. Der Server läuft dann wieder ohne WAF.

## Hinweise

- **Gebaut gegen das httpd-2.4.66-VS17-SDK** (Apache Lounge bietet 2.4.62 nicht
  mehr an). Die 2.4.x-Modul-ABI ist stabil (MMN-Major identisch), ModSecurity
  nutzt keine neuen 2.4.66-APIs — läuft auf 2.4.62. Sollte `httpd -t` dennoch
  einen Symbolfehler melden: Apache auf 2.4.66 VS17 aktualisieren (Zip liegt im
  Repo unter `sdk/`, SHA256-geprüft). Das Update ist ohnehin empfohlen —
  2.4.62 ist von 09/2024 und hat offene CVEs.
- Kein OWASP CRS in dieser Stufe — bewusst nur die Legacy-PHP-Guard-Regeln
  (siehe Absicherungsplan). CRS kann später additiv in DetectionOnly getestet
  werden.
- Das Modul ist ohne curl/SecRemoteRules, ohne Lua und ohne YAJL (JSON-Body-
  Parsing) gebaut — minimale Angriffsfläche. Wird JSON-Inspektion benötigt,
  Build mit YAJL erweitern.
