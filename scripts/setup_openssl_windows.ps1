$ErrorActionPreference = "Stop"

choco install openssl --no-progress -y

$searchRoots = @(
  $env:ProgramFiles,
  ${env:ProgramFiles(x86)},
  $env:ChocolateyInstall,
  "C:\tools",
  "C:\ProgramData\chocolatey"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

$header = $null
foreach ($root in $searchRoots) {
  $header = Get-ChildItem -Path $root -Filter ssl.h -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '[\\/]include[\\/]openssl[\\/]ssl\.h$' } |
    Select-Object -First 1
  if ($header) {
    break
  }
}

if (-not $header) {
  throw "OpenSSL header ssl.h was not found under: $($searchRoots -join ', ')"
}

$includeDir = Split-Path (Split-Path $header.FullName -Parent) -Parent
$opensslDir = Split-Path $includeDir -Parent

$libCrypto = Get-ChildItem -Path $opensslDir -Filter libcrypto.lib -File -Recurse -ErrorAction SilentlyContinue |
  Select-Object -First 1
if (-not $libCrypto) {
  throw "OpenSSL import library libcrypto.lib was not found under $opensslDir"
}

$libDir = Split-Path $libCrypto.FullName -Parent
$opensslExe = Get-ChildItem -Path $opensslDir -Filter openssl.exe -File -Recurse -ErrorAction SilentlyContinue |
  Select-Object -First 1

"OPENSSL_DIR=$opensslDir" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
"OPENSSL_INCLUDE_DIR=$includeDir" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
"OPENSSL_LIB_DIR=$libDir" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append

if ($opensslExe) {
  $binDir = Split-Path $opensslExe.FullName -Parent
  $binDir | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
}

Write-Host "Resolved OpenSSL directory: $opensslDir"
Write-Host "Resolved OpenSSL include dir: $includeDir"
Write-Host "Resolved OpenSSL lib dir: $libDir"
