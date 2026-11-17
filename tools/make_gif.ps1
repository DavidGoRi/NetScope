<#
.SYNOPSIS
    Builds docs/demo.gif (dashboard tour) from the fictitious demo network.
.DESCRIPTION
    Renders the demo with tools/make_demo.py, captures six views with headless
    Microsoft Edge and joins them with FFmpeg cross-fades into a 960x540 GIF.
    Requires Python, Microsoft Edge and FFmpeg on PATH.
#>
param([string] $Output = (Join-Path $PSScriptRoot '..\docs\demo.gif'))

$ErrorActionPreference = 'Stop'
$work = Join-Path ([IO.Path]::GetTempPath()) ("netscope-gif-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    python (Join-Path $PSScriptRoot 'make_demo.py') $work | Out-Null
    $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
              "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edge) { throw 'Microsoft Edge not found' }
    $url = 'file:///' + ((Join-Path $work 'index.html') -replace '\\', '/')
    $views = '?lang=en', '?lang=en#findings', '?lang=en#changes',
             '?lang=en#device=10.20.0.10', '?lang=en#device=10.20.0.31', '?lang=es'
    $frames = @()
    for ($i = 0; $i -lt $views.Count; $i++) {
        $frame = Join-Path $work "frame$i.png"
        Start-Process -FilePath $edge -Wait -WindowStyle Hidden -ArgumentList @(
            '--headless=new', '--disable-gpu', '--hide-scrollbars', "--user-data-dir=$work\profile",
            '--window-size=1280,720', "--screenshot=$frame", "$url$($views[$i])")
        $frames += $frame
    }

    # Each view shows for $hold seconds and cross-fades into the next one in $fade seconds.
    $hold, $fade = 2.4, 0.4
    $inputs = foreach ($frame in $frames) { '-loop', '1', '-t', "$hold", '-i', $frame }
    $chain, $last = @(), '[0:v]'
    for ($i = 1; $i -lt $frames.Count; $i++) {
        $offset = [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:0.0#}', $i * ($hold - $fade))
        $chain += "$last[$($i):v]xfade=transition=fade:duration=$($fade):offset=$offset[x$i]"
        $last = "[x$i]"
    }
    $filter = ($chain -join ';') + ";$($last)fps=12,scale=960:-1:flags=lanczos,split[a][b];" +
              '[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=sierra2_4a'
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & ffmpeg -v error -y @inputs -filter_complex $filter -loop 0 $Output
    $ErrorActionPreference = $previous
    if ($LASTEXITCODE) { throw "ffmpeg failed ($LASTEXITCODE)" }
    Get-Item $Output
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
