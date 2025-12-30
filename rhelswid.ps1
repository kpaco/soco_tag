### .\new-swid.ps1 -swid 1234 -swname MyApp -vendor Oracle -chk RC
## ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ##
param(
    [Parameter(Mandatory=$true)] [string]$swid,
	[Parameter(Mandatory=$true)] [string]$vendor,
    [Parameter(Mandatory=$true)] [string]$swname,
	[Parameter(Mandatory=$true)] [string]$ver,
    [Parameter(Mandatory=$false)] [string]$chk
)

# Script folder
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Hardcoded source file
$sourceFile = Join-Path $scriptDir "SWID00_RH.txt"
if (-not (Test-Path $sourceFile)) {
    Write-Error "Source file not found: $sourceFile"
    exit 1
}

# Build output folder name dynamically
$outputDirName = "SWID00" + "$swid" + "_" + "$swname"
##if ($os) { $outputDirName += "_$os" }
##if ($chk) { $outputDirName += "_$chk" }
$outputDir = Join-Path $scriptDir $outputDirName

# Create directory if it doesn't exist
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Output file path
$outputFile = Join-Path $outputDir "$outputDirName.txt"

# Read source content
$content = Get-Content $sourceFile

# Replace mandatory placeholders
##$swid="SWID00" + $swid
$content = $content -replace "SW1D", $swid
$content = $content -replace "VEND0R", $vendor
$content = $content -replace "SWN@ME", $swname
$content = $content -replace "V0ERS", $ver

# Replace optional placeholders if supplied; else remove
##$content = if ($os) { $content -replace "OS", $os } else { $content -replace "OS_PLACEHOLDER", "" }
$content = if ($chk) { $content -replace "CHK", $chk } else { $content -replace "CHK_PLACEHOLDER", "" }

# Write output
Set-Content -Path $outputFile -Value $content

Write-Host "✅ Output file created at $outputFile"
