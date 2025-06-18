# Comprehensive Security Scan Script (PowerShell)
# Runs a full scan with all advanced features enabled

# Check if a target is provided
param (
    [Parameter(Mandatory=$true)]
    [string]$target
)

# Set up output directory and report file
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$safeTargetName = $target -replace '[^a-zA-Z0-9]', '_'
$outputDir = "./reports/$($safeTargetName)-$timestamp"
$reportFile = "$outputDir/comprehensive-report.json"

# Create output directory
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "🔍 Starting comprehensive security scan for $target"
Write-Host "📁 Results will be saved to $outputDir"

# Run the comprehensive scan
node ./bin/cli.js scan $target `
    --advanced `
    --ai-scan `
    --api-scan `
    --auth-scan `
    --cloud-scan `
    --deps-scan `
    --puppeteer `
    --client-side-vulns `
    --extract-links `
    --content-security `
    --screenshot `
    --screenshot-path "$outputDir/screenshot.png" `
    --save-artifacts `
    --report-format "json,html,pdf" `
    --output $reportFile `
    --interactive-dashboard

# Keep this script running until user presses Ctrl+C (to keep dashboard alive)
Write-Host "Press Ctrl+C to stop the dashboard server and exit."
Wait-Event -Timeout ([int]::MaxValue)
