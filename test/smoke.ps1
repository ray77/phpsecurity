# Smoke test: loads mod_security2.so in the Apache Lounge tree, starts httpd,
# verifies that legacy-php-guard rules block malformed/oversized requests and
# that benign requests pass through.
param(
    [Parameter(Mandatory)][string]$Apache,     # Apache24 directory
    [Parameter(Mandatory)][string]$Module,     # path to mod_security2.so
    [Parameter(Mandatory)][string]$ModsecSrc,  # ModSecurity source tree
    [Parameter(Mandatory)][string]$Rules       # legacy-php-guard.conf
)
$ErrorActionPreference = 'Stop'
$Apache = (Resolve-Path $Apache).Path
$aroot = $Apache -replace '\\', '/'

Copy-Item $Module  "$Apache\modules\mod_security2.so" -Force
Copy-Item "$ModsecSrc\modsecurity.conf-recommended" "$Apache\conf\modsecurity.conf" -Force
Copy-Item "$ModsecSrc\unicode.mapping" "$Apache\conf\unicode.mapping" -Force
Copy-Item $Rules "$Apache\conf\legacy-php-guard.conf" -Force
Set-Content "$Apache\htdocs\index.html" '<html>ok</html>' -Encoding ascii

# Adapt recommended conf: Windows paths, engine On for the test
$conf = Get-Content "$Apache\conf\modsecurity.conf" -Raw
$conf = $conf -replace 'SecRuleEngine DetectionOnly', 'SecRuleEngine On'
$conf = $conf -replace 'SecTmpDir /tmp/', "SecTmpDir `"$aroot/logs/`""
$conf = $conf -replace 'SecDataDir /tmp/', "SecDataDir `"$aroot/logs/`""
$conf = $conf -replace 'SecAuditLog /var/log/modsec_audit.log', "SecAuditLog `"$aroot/logs/modsec_audit.log`""
# SecUnicodeMapFile ist relativ zur Config-Datei; unicode.mapping liegt daneben in conf/
Set-Content "$Apache\conf\modsecurity.conf" $conf -Encoding ascii

@"
ServerRoot "$aroot"
Listen 127.0.0.1:8081
ServerName localhost
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule unique_id_module modules/mod_unique_id.so
LoadModule security2_module modules/mod_security2.so
DocumentRoot "$aroot/htdocs"
<Directory "$aroot/htdocs">
    Require all granted
</Directory>
ErrorLog logs/test-error.log
PidFile logs/test-httpd.pid
Include conf/modsecurity.conf
Include conf/legacy-php-guard.conf
"@ | Set-Content "$Apache\conf\test-modsec.conf" -Encoding ascii

Write-Host "== httpd -t (config + module load check)"
& "$Apache\bin\httpd.exe" -t -f "$aroot/conf/test-modsec.conf"
if ($LASTEXITCODE -ne 0) { throw "httpd -t failed" }

Write-Host "== starting httpd"
$proc = Start-Process "$Apache\bin\httpd.exe" -ArgumentList '-f', "$aroot/conf/test-modsec.conf" -PassThru -NoNewWindow
Start-Sleep -Seconds 4
if ($proc.HasExited) {
    Get-Content "$Apache\logs\test-error.log" -ErrorAction SilentlyContinue
    throw "httpd exited immediately"
}

$failures = @()
function Check([string]$name, [string]$actual, [string[]]$expected) {
    if ($expected -contains $actual) {
        Write-Host ("PASS {0}: HTTP {1}" -f $name, $actual)
    } else {
        Write-Host ("FAIL {0}: HTTP {1} (expected {2})" -f $name, $actual, ($expected -join '/'))
        $script:failures += $name
    }
}

$base = 'http://127.0.0.1:8081/'
$b = 'xxxBOUNDARYxxx'
$tmp = $env:TEMP

try {
    # 1. Benign GET -> 200
    $code = & curl.exe -s -o NUL -w '%{http_code}' $base
    Check 'benign GET' $code @('200')

    # 2. Benign multipart POST (1 field + 1 small file) -> must NOT be blocked.
    #    Target is a static file, so Apache answers 405 after ModSecurity let it through.
    $body = "--$b`r`n" +
            "Content-Disposition: form-data; name=`"field1`"`r`n`r`nvalue1`r`n" +
            "--$b`r`n" +
            "Content-Disposition: form-data; name=`"file1`"; filename=`"a.txt`"`r`n" +
            "Content-Type: text/plain`r`n`r`nhello`r`n" +
            "--$b--`r`n"
    [IO.File]::WriteAllText("$tmp\mp-ok.bin", $body, [Text.Encoding]::ASCII)
    $code = & curl.exe -s -o NUL -w '%{http_code}' -H "Content-Type: multipart/form-data; boundary=$b" --data-binary "@$tmp\mp-ok.bin" $base
    Check 'benign multipart (not blocked)' $code @('405', '200')

    # 3. 350 GET args -> rule 1100007 -> 400
    $qs = (0..349 | ForEach-Object { "a$_=1" }) -join '&'
    $code = & curl.exe -s -o NUL -w '%{http_code}' "$base`?$qs"
    Check 'excessive args' $code @('400')

    # 4. Multipart part with 250 header lines -> rule 1100009 (or parser error rule) -> 400
    $hdrs = ((1..250 | ForEach-Object { "X-Pad-${_}: x" }) -join "`r`n")
    $body = "--$b`r`n" +
            "Content-Disposition: form-data; name=`"f`"`r`n" +
            $hdrs + "`r`n`r`nv`r`n" +
            "--$b--`r`n"
    [IO.File]::WriteAllText("$tmp\mp-hdrs.bin", $body, [Text.Encoding]::ASCII)
    $code = & curl.exe -s -o NUL -w '%{http_code}' -H "Content-Type: multipart/form-data; boundary=$b" --data-binary "@$tmp\mp-hdrs.bin" $base
    Check 'excessive multipart headers' $code @('400')

    # 5. Duplicate Content-Disposition in one part -> rule 1100002 -> 400
    $body = "--$b`r`n" +
            "Content-Disposition: form-data; name=`"g`"`r`n" +
            "Content-Disposition: form-data; name=`"g`"`r`n`r`nv`r`n" +
            "--$b--`r`n"
    [IO.File]::WriteAllText("$tmp\mp-dup.bin", $body, [Text.Encoding]::ASCII)
    $code = & curl.exe -s -o NUL -w '%{http_code}' -H "Content-Type: multipart/form-data; boundary=$b" --data-binary "@$tmp\mp-dup.bin" $base
    Check 'duplicate part header' $code @('400')

    # 6. Unmatched boundary -> blocked. Fataler Multipart-Abbruch endet je nach
    #    Pfad als 400 (Regel) oder 500 (Parser bricht Request intern ab).
    $body = "--$b`r`n" +
            "Content-Disposition: form-data; name=`"h`"`r`n`r`nv`r`n" +
            "--WRONGBOUNDARY--`r`n"
    [IO.File]::WriteAllText("$tmp\mp-bnd.bin", $body, [Text.Encoding]::ASCII)
    $code = & curl.exe -s -o NUL -w '%{http_code}' -H "Content-Type: multipart/form-data; boundary=$b" --data-binary "@$tmp\mp-bnd.bin" $base
    Check 'unmatched boundary (blocked)' $code @('400', '500')
}
finally {
    Write-Host "== stopping httpd"
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "== ModSecurity messages in error log:"
    Get-Content "$Apache\logs\test-error.log" -ErrorAction SilentlyContinue |
        Select-String 'ModSecurity' | ForEach-Object { $_.Line } | Select-Object -First 40
}

if ($failures.Count -gt 0) {
    throw ("smoke test failed: " + ($failures -join ', '))
}
Write-Host "== all smoke tests passed"
