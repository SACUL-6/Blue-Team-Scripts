param([Parameter(Mandatory)][string]$Ext)

$work = Join-Path $env:TEMP "ext_$Ext"
New-Item -ItemType Directory -Force $work | Out-Null
$crx = Join-Path $work "ext.crx"
$url = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=130.0&acceptformat=crx2,crx3&x=id%3D$Ext%26uc"

Invoke-WebRequest -Uri $url -OutFile $crx -UseBasicParsing

$b = [IO.File]::ReadAllBytes($crx)
if ($b.Length -lt 16 -or [Text.Encoding]::ASCII.GetString($b,0,4) -ne 'Cr24') {
    throw "Download is not a CRX file (size $($b.Length)). Wrong ID, or the Web Store has no copy."
}

# Skip the CRX header to find where the zip data starts
$ver = [BitConverter]::ToUInt32($b,4)
switch ($ver) {
    3 { $off = 12 + [BitConverter]::ToUInt32($b,8) }
    2 { $off = 16 + [BitConverter]::ToUInt32($b,8) + [BitConverter]::ToUInt32($b,12) }
    default { throw "Unsupported CRX version $ver" }
}
$out = New-Object byte[] ($b.Length - $off)
[Array]::Copy($b, $off, $out, 0, $out.Length)
$zip = Join-Path $work "ext.zip"
[IO.File]::WriteAllBytes($zip, $out)

$src = Join-Path $work "src"
Expand-Archive -Path $zip -DestinationPath $src -Force

# Manifest first, then the background script(s) it names
$manifestPath = Join-Path $src "manifest.json"
Get-Content $manifestPath
$m = Get-Content $manifestPath -Raw | ConvertFrom-Json
$bg = @()
if ($m.background.service_worker) { $bg += $m.background.service_worker }
if ($m.background.scripts)        { $bg += $m.background.scripts }
foreach ($f in $bg) {
    Write-Host "`n===== $f =====" -ForegroundColor Cyan
    Get-Content (Join-Path $src $f)
}