# phpsecurity — ModSecurity 2.9.15 Win64-Build für Legacy-PHP-Server

WAF-Schutzschicht für einen Windows-Server mit Apache Lounge 2.4.62 (Win64/VS17),
PHP 5.3.29 (mod_php) und Joomla. Statt des riskanten PHP-Austauschs wird
ModSecurity 2.9.15 mit eigenen Legacy-PHP-Guard-Regeln vorgeschaltet
(Multipart-/Request-Parsing-Angriffsklasse, siehe Absicherungsplan).

## Build

GitHub Actions baut `mod_security2.so` auf `windows-2022` (Visual Studio 2022
= VS17, passend zur Apache-Lounge-VS17-Serie):

- **ModSecurity 2.9.15** (Quelltarball, SHA256-gepinnt)
- **PCRE2** statisch aus dem Apache-Lounge-SDK (`pcre2-8-static.lib`) + JIT
- **libxml2 2.14.6** statisch, minimal (ohne iconv/zlib/lzma/http)
- ohne curl/SecRemoteRules, ohne Lua, ohne YAJL
- Apache-SDK: `sdk/httpd-2.4.66-win64-VS17.zip` (im Repo, SHA256-geprüft)

Trigger: Push auf `main` oder manuell (*Actions → Build mod_security2 Win64
VS17 → Run workflow*). Artefakt: `mod_security2-2.9.15-win64-VS17`
(Modul + Konfiguration + Regeln + Install-Anleitung + BUILDINFO).

Jeder Build durchläuft `test/smoke.ps1`: Modul wird in echtem httpd geladen,
Angriffsmuster (zu viele Argumente, exzessive/duplizierte/kaputte
Multipart-Header) müssen 400 liefern, gutartige Requests durchgehen.

## Layout

```
CMakeLists.txt                     Build des Apache-Moduls (MSVC)
.github/workflows/build-modsecurity.yml
rules/legacy-php-guard.conf        WAF-Regeln (IDs 1100001-1100009)
test/smoke.ps1                     Funktionstest im CI
docs/INSTALL-SERVER.md             Installation + Rollout auf dem Server
sdk/httpd-2.4.66-win64-VS17.zip    Apache Lounge SDK (Build + Smoke-Test)
```

## Server-Installation

Siehe [docs/INSTALL-SERVER.md](docs/INSTALL-SERVER.md) — Kurzfassung:
Artefakt entpacken, Dateien nach `D:\Apache24`, `httpd.conf` erweitern,
Rollout zwingend über `SecRuleEngine DetectionOnly`, erst nach
Log-Auswertung auf `On` schalten.
