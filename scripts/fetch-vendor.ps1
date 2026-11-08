# Downloads pdf.js into ui\vendor\ so PDF preview works without internet.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$Version = "3.11.174"
$Dest = "ui\vendor\pdfjs"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
foreach ($f in @("pdf.min.js", "pdf.worker.min.js")) {
  Invoke-WebRequest -Uri "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/$Version/$f" -OutFile (Join-Path $Dest $f)
}
Write-Host "pdf.js $Version saved to $Dest"
