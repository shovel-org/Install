# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>

<#
.SYNOPSIS
    Generic installer to install any scoop fork hosted on GitHub.
    Soon will be fully rebranded to Shovel.
.PARAMETER ScoopDir
    Specifies directory to install. $env:SCOOP could be used instead.
    Scoop will be installed to '$env:USERPROFILE\Shovel' if not specificed.
.PARAMETER ScoopGlobalDir
    Specifies global app directory. $env:SCOOP_GLOBAL could be used instead.
    Global app will be installed to '$env:ProgramData\Shovel' if not specificed.
.PARAMETER ScoopCacheDir
    Specifies cache directory. $env:SCOOP_CACHE could be used instead.
    Cache directory will be '$ScoopDir\cache' if not specificed.
.PARAMETER ScoopRepo
    Specifies Scoop repository URL. $env:SCOOP_REPO could be used instead.
    'https://github.com/Ash258/Scoop-Core' will be used when none is provided.
.PARAMETER ScoopBranch
    Specific branch of scoop-core to be downloaded. $env:SCOOP_BRANCH could be used instead.
    'main' will be used if not specificed.
.PARAMETER InstallerCacheDir
    Specify local directory where required files are located to eliminate the need to download.
    Scoop cache directory will be used if not specificed.
    Following files are supported:
        Core.zip
        Base.zip
        main.zip
    Place them to the specified directory and set this parameter to the directory.
.PARAMETER NoProxy
    Specifies bypass system proxy or not while installation.
.PARAMETER Proxy
    Specifies proxy to use while installation.
.PARAMETER ProxyCredential
    Specifies credential for the prxoy.
.PARAMETER ProxyUseDefaultCredentials
    Use the credentials of the current user for the proxy server that is specified by the -Proxy parameter.
.PARAMETER RunAsAdmin
    Force to run the installer as administrator.
.PARAMETER SkipRobocopy
    Do not check existence of robocopy.exe in windows PATH.
    Useful for nanocore installations.
.PARAMETER SkipGit
    Use this option if git is installed, but should not be used.
    Useful only when git is installed, but there is need to install from cached files due to network issues.
.LINK
    https://scoop.sh
.LINK
    https://github.com/ScoopInstaller/Scoop/wiki
#>
[CmdletBinding()]
param(
    [String] $ScoopDir,
    [String] $ScoopGlobalDir,
    [String] $ScoopCacheDir,
    [String] $ScoopRepo,
    [String] $ScoopBranch,
    [String] $InstallerCacheDir,
    [Switch] $NoProxy,
    [Uri] $Proxy,
    [System.Management.Automation.PSCredential] $ProxyCredential,
    [Switch] $ProxyUseDefaultCredentials,
    [Switch] $RunAsAdmin,
    [Switch] $SkipRobocopy,
    [Switch] $SkipGit
)

# Disable StrictMode in this script
Set-StrictMode -Off

#region Functions
function _firstNonNullOrEmpty([Array] $Arguments) {
    return $Arguments | Where-Object { -not [String]::IsNullOrEmpty($_) } | Select-Object -First 1
}

function Write-InstallInfo {
    param(
        [Parameter(Mandatory, Position = 0)]
        [String] $String,
        [Parameter(Position = 1)]
        [System.ConsoleColor] $ForegroundColor = $host.UI.RawUI.ForegroundColor
    )

    $backup = $host.UI.RawUI.ForegroundColor

    if ($ForegroundColor -ne $host.UI.RawUI.ForegroundColor) {
        $host.UI.RawUI.ForegroundColor = $ForegroundColor
    }

    Write-Output "$String"

    $host.UI.RawUI.ForegroundColor = $backup
}

function Deny-Install {
    param(
        [String] $message,
        [Int] $errorCode = 1
    )

    Write-InstallInfo -String $message -ForegroundColor 'DarkRed'
    Write-InstallInfo 'Abort.'

    # Don't abort if invoked with iex that would close the PS session
    if ($IS_EXECUTED_FROM_IEX) {
        break
    } else {
        exit $errorCode
    }
}

function Test-ValidateParameter {
    if ($null -eq $Proxy -and ($null -ne $ProxyCredential -or $ProxyUseDefaultCredentials)) {
        Deny-Install 'Provide a valid proxy URI for the -Proxy parameter when using the -ProxyCredential or -ProxyUseDefaultCredentials.'
    }

    if ($ProxyUseDefaultCredentials -and $null -ne $ProxyCredential) {
        Deny-Install 'ProxyUseDefaultCredentials conflicts with ProxyCredential. Do not use the -ProxyCredential and -ProxyUseDefaultCredentials together.'
    }
}

function Test-IsAdministrator {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Prerequisite {
    # Scoop requires PowerShell 5 at least
    if (($PSVersionTable.PSVersion.Major) -lt 5) {
        Deny-Install 'PowerShell 5 or later is required to run Scoop. Go to https://microsoft.com/powershell to get the latest version of PowerShell.'
    }

    # Scoop requires TLS 1.2 SecurityProtocol, which exists in .NET Framework 4.5+
    if ([System.Enum]::GetNames([System.Net.SecurityProtocolType]) -notcontains 'Tls12') {
        Deny-Install 'Scoop requires .NET Framework 4.5+ to work. Go to https://microsoft.com/net/download to get the latest version of .NET Framework.'
    }

    # Ensure Robocopy.exe is accessible
    if (!$SkipRobocopy) {
        if (!([bool](Get-Command -Name 'robocopy' -ErrorAction 'SilentlyContinue'))) {
            Deny-Install 'Scoop requires ''C:\Windows\System32\Robocopy.exe'' to work. Please make sure ''C:\Windows\System32'' is in your PATH.'
        }
    }

    # Detect if RunAsAdministrator, there is no need to run as administrator when installing Scoop.
    if (!$RunAsAdmin -and (Test-IsAdministrator)) {
        Deny-Install 'Running the installer as administrator is disabled by default, use -RunAsAdmin parameter if you know what you are doing.'
    }

    # Show notification to change execution policy
    $allowedExecutionPolicy = @('Unrestricted', 'RemoteSigned', 'ByPass')
    if ((Get-ExecutionPolicy).ToString() -notin $allowedExecutionPolicy) {
        Deny-Install "PowerShell requires an execution policy in [$($allowedExecutionPolicy -join ', ')] to run Scoop. For example, to set the execution policy to 'RemoteSigned' please run 'Set-ExecutionPolicy RemoteSigned -Scope CurrentUser'."
    }

    # Test if scoop is installed, by checking if scoop command exists.
    if ([bool](Get-Command -Name 'scoop' -ErrorAction 'SilentlyContinue')) {
        Deny-Install "Scoop is already installed. Run 'scoop update' to get the latest version."
    }
}

function Optimize-SecurityProtocol {
    # .NET Framework 4.7+ has a default security protocol called 'SystemDefault',
    # which allows the operating system to choose the best protocol to use.
    # If SecurityProtocolType contains 'SystemDefault' (means .NET4.7+ detected)
    # and the value of SecurityProtocol is 'SystemDefault', just do nothing on SecurityProtocol,
    # 'SystemDefault' will use TLS 1.2 if the webrequest requires.
    $isNewerNetFramework = ([System.Enum]::GetNames([System.Net.SecurityProtocolType]) -contains 'SystemDefault')
    $isSystemDefault = ([System.Net.ServicePointManager]::SecurityProtocol.Equals([System.Net.SecurityProtocolType]::SystemDefault))

    # If not, change it to support TLS 1.2
    if (!($isNewerNetFramework -and $isSystemDefault)) {
        # Set to TLS 1.2 (3072), then TLS 1.1 (768), and TLS 1.0 (192). Ssl3 has been superseded,
        # https://docs.microsoft.com/en-us/dotnet/api/system.net.securityprotocoltype?view=netframework-4.5
        [System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192
    }
}

function Get-Downloader {
    $downloadSession = New-Object System.Net.WebClient

    # Set proxy to null if NoProxy is specificed
    if ($NoProxy) {
        $downloadSession.Proxy = $null
    } elseif ($Proxy) {
        # Prepend protocol if not provided
        if (!$Proxy.IsAbsoluteUri) {
            $Proxy = New-Object System.Uri('http://' + $Proxy.OriginalString)
        }

        $Proxy = New-Object System.Net.WebProxy($Proxy)

        if ($null -ne $ProxyCredential) {
            $Proxy.Credentials = $ProxyCredential.GetNetworkCredential()
        } elseif ($ProxyUseDefaultCredentials) {
            $Proxy.UseDefaultCredentials = $true
        }

        $downloadSession.Proxy = $Proxy
    }

    return $downloadSession
}

function Test-isFileLocked {
    param([String] $path)

    $file = New-Object System.IO.FileInfo $path

    if (!(Test-Path -LiteralPath $path -PathType 'Leaf')) { return $false }

    try {
        $stream = $file.Open(
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
        if ($stream) {
            $stream.Close()
        }
        return $false
    } catch {
        # The file is locked by a process.
        return $true
    }
}

function Expand-ZipArchive {
    param(
        [String] $path,
        [String] $to
    )

    if (!(Test-Path -LiteralPath $path -PathType 'Leaf')) {
        Deny-Install "Unzip failed: cannot find $path to unzip."
    }

    # Check if the zip file is locked, by antivirus software for example
    $retries = 0
    while ($retries -le 10) {
        if ($retries -eq 10) {
            Deny-Install 'Unzip failed: cannot unzip because a process is locking the file.'
        }
        if (Test-isFileLocked $path) {
            Write-InstallInfo "Waiting for $path to be unlocked by another process... ($retries/10)"
            $retries++
            Start-Sleep -Seconds 2
        } else {
            break
        }
    }

    Write-InstallInfo "Unziping '$path' to '$to'"

    # PowerShell 5+: use Expand-Archive to extract zip files
    Microsoft.PowerShell.Archive\Expand-Archive -Path $path -DestinationPath $to -Force
}

function Out-UTF8File {
    param(
        [Parameter(Mandatory, Position = 0)]
        [Alias('Path', 'LiteralPath', 'FilePath')]
        [System.IO.FileInfo] $File,
        $Content,
        $LineEnd = "`r`n",
        [Parameter(ValueFromPipeline)]
        [PSObject] $InputObject
    )

    begin {
        if ($null -eq $Content) { return }
    }

    process {
        $c = $Content -join $LineEnd
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            Set-Content -LiteralPath $File -Value $c -Encoding 'utf8NoBOM'
        } else {
            [System.IO.File]::WriteAllText($File, $c)
        }
    }
}

function Import-ScoopShim {
    Write-InstallInfo 'Creating shim...'

    # The scoop executable
    $path = "$SCOOP_APP_DIR\bin\scoop.ps1"

    if (!(Test-Path -LiteralPath $SCOOP_SHIMS_DIR -PathType 'Container')) {
        New-Item -Path $SCOOP_SHIMS_DIR -Type 'Directory' | Out-Null
        Write-Verbose "Created shim directory: $SCOOP_SHIMS_DIR"
    }
    if ($RunAsAdmin) {
        if (!(Test-Path -LiteralPath $SCOOP_GLOBAL_SHIMS_DIR -PathType 'Container')) {
            New-Item -Path $SCOOP_GLOBAL_SHIMS_DIR -Type 'Directory' -Force | Out-Null
            Write-Verbose "Created global shim directory: $SCOOP_GLOBAL_SHIMS_DIR"
        }
    }

    # The shim
    $shim = "$SCOOP_SHIMS_DIR\shovel"

    # Convert to relative path
    Push-Location $SCOOP_SHIMS_DIR
    $relativePath = Resolve-Path -Relative $path
    Pop-Location

    # Setting PSScriptRoot in Shim if it is not defined, so the shim doesn't break in PowerShell 2.0
    Out-UTF8File -LiteralPath "$shim.ps1" -Content @"
if (!(Test-Path Variable:PSScriptRoot)) { `$PSScriptRoot = Split-Path `$MyInvocation.MyCommand.Path -Parent }
`$path = Join-Path "`$PSScriptRoot" "$relativePath"
if (`$MyInvocation.ExpectingInput) { `$input | & `$path @args } else { & `$path @args }
"@
    Write-Verbose 'Created shim - ps1'

    # Make scoop accessible from cmd.exe
    Out-UTF8File -LiteralPath "$shim.cmd" -Content @"
@echo off
setlocal enabledelayedexpansion
set args=%*
:: replace problem characters in arguments
set args=%args:"='%
set args=%args:(=``(%
set args=%args:)=``)%
set invalid="='
if !args! == !invalid! ( set args= )
powershell -NoProfile -ExecutionPolicy Unrestricted "& '$path' %args%; exit `$LASTEXITCODE"
"@
    Write-Verbose 'Created shim - cmd'

    # Make scoop accessible from bash or other posix shell
    Out-UTF8File -LiteralPath $shim -LineEnd "`n" -Content @(
        '#!/bin/sh',
        "powershell.exe -NoProfile -NoLogo -ExecutionPolicy Unrestricted `"$path`" `"$@`"",
        ''
    )
    Write-Verbose 'Created shim - bash'

    # Backwards compatible with scoop
    Get-ChildItem $SCOOP_SHIMS_DIR -Filter 'shovel.*' |
        Copy-Item -Destination { Join-Path $_.Directory.FullName (($_.BaseName -replace 'shovel', 'scoop') + $_.Extension) }
    Write-Verbose 'Created scoop commands'
}

function Get-Env {
    param(
        [String] $name,
        [Switch] $global
    )

    $target = if ($global) { 'Machine' } else { 'User' }
    return [Environment]::GetEnvironmentVariable($name, $target)
}

function Add-ShimsDirToPath {
    # Get $env:PATH of current user
    $userEnvPath = Get-Env 'PATH'
    $newUserEnvPath = "$SCOOP_SHIMS_DIR;$userEnvPath"

    if ($userEnvPath -notmatch [Regex]::Escape($SCOOP_SHIMS_DIR)) {
        $h = (Get-PSProvider 'FileSystem').Home
        if (!$h.EndsWith('\')) { $h += '\' }

        if ($h -ne '\') {
            $friendlyPath = $SCOOP_SHIMS_DIR -replace ([Regex]::Escape($h)), '~\'
            Write-InstallInfo "Adding $friendlyPath to your path."
        } else {
            Write-InstallInfo "Adding $SCOOP_SHIMS_DIR to your path."
        }

        # For future sessions
        [System.Environment]::SetEnvironmentVariable('PATH', $userEnvPath, 'User')
        # For current session
        $env:PATH = $userEnvPath
    }

    # Get $env:PATH of machine
    $globalEnvPath = Get-Env 'PATH' -global
    $newGlobalEnvPath = "${SCOOP_GLOBAL_SHIMS_DIR};${globalEnvPath}"

    if ($globalEnvPath -notmatch [Regex]::Escape($SCOOP_GLOBAL_SHIMS_DIR)) {
        if (Test-IsAdministrator) {
            Write-InstallInfo "Adding ${SCOOP_GLOBAL_SHIMS_DIR} to system-wide PATH."
            # For future sessions
            [System.Environment]::SetEnvironmentVariable('PATH', $newGlobalEnvPath, 'Machine')
            # For current session
            $env:PATH = $newGlobalEnvPath
        }
    }

    # Nanoserver does not have user specific path
    if ($env:POWERSHELL_DISTRIBUTION_CHANNEL -like '*nanoserver*') {
        $newGlobalEnvPath = "${SCOOP_SHIMS_DIR};$newGlobalEnvPath"
        # For future sessions
        [System.Environment]::SetEnvironmentVariable('PATH', $newGlobalEnvPath, 'Machine')
        # For current session
        $env:PATH = $newGlobalEnvPath
    }
}

function Use-Config {
    if (!(Test-Path -LiteralPath $SCOOP_CONFIG_FILE -PathType 'Leaf')) {
        return $null
    }

    try {
        return (Get-Content $SCOOP_CONFIG_FILE -Raw | ConvertFrom-Json -ErrorAction 'Stop')
    } catch {
        Deny-Install "ERROR loading ${SCOOP_CONFIG_FILE}: $($_.Exception.Message)"
    }
}

function Add-Config {
    param (
        [Parameter(Mandatory, Position = 0)]
        [String] $Name,
        [Parameter(Mandatory, Position = 1)]
        $Value
    )

    $scoopConfig = Use-Config

    # Cast to boolean
    if (($Value -eq [bool]::TrueString) -or ($Value -eq [bool]::FalseString)) {
        $Value = [System.Convert]::ToBoolean($Value)
    }

    if ($scoopConfig -is [System.Management.Automation.PSObject]) {
        if ($null -eq $scoopConfig.$Name) {
            $scoopConfig | Add-Member -MemberType 'NoteProperty' -Name $Name -Value $Value
        } else {
            $scoopConfig.$Name = $Value
        }
    } else {
        $baseDir = Split-Path -Path $SCOOP_CONFIG_FILE
        if (!(Test-Path -LiteralPath $baseDir -PathType 'Container')) {
            New-Item -Path $baseDir -Type 'Directory' | Out-Null
        }

        $scoopConfig = New-Object PSObject
        $scoopConfig | Add-Member -MemberType 'NoteProperty' -Name $Name -Value $Value
    }

    if ($null -eq $Value) {
        $scoopConfig.PSObject.Properties.Remove($Name)
    }

    Out-UTF8File -LiteralPath $SCOOP_CONFIG_FILE -Content (ConvertTo-Json $scoopConfig)

    return $scoopConfig
}

function Add-DefaultConfig {
    $user = if (Test-IsAdministrator) { 'Machine' } else { 'User' }

    if (!(Get-Env 'SCOOP')) {
        [Environment]::SetEnvironmentVariable('SCOOP', $SCOOP_DIR, 'User')
        $env:SCOOP = $SCOOP_DIR
    }

    if (!(Get-Env 'SCOOP_GLOBAL' -global)) {
        [Environment]::SetEnvironmentVariable('SCOOP_GLOBAL', $SCOOP_GLOBAL_DIR, $user)
        $env:SCOOP_GLOBAL = $SCOOP_GLOBAL_DIR
    }

    if (!(Get-Env 'SCOOP_CACHE' -global) -or !(Get-Env 'SCOOP_CACHE')) {
        [Environment]::SetEnvironmentVariable('SCOOP_CACHE', $SCOOP_CACHE_DIR, $user)
        $env:SCOOP_CACHE = $SCOOP_CACHE_DIR
    }

    Add-Config -Name 'lastUpdate' -Value ([System.DateTime]::Now.AddHours(1).ToString('258|yyyy-MM-dd HH:mm:ss')) | Out-Null
    Add-Config -Name 'SCOOP_REPO' -Value $SCOOP_REPO | Out-Null
    Add-Config -Name 'SCOOP_BRANCH' -Value $SCOOP_BRANCH | Out-Null
    Add-Config -Name 'MSIEXTRACT_USE_LESSMSI' -Value $true | Out-Null
    if ($SkipRobocopy) {
        Add-Config -Name 'core.preferMoveItem' -Value $true | Out-Null
    }
}

function Get-AllRequiredFile {
    $SCOOP_MAIN_BUCKET_DIR = "${SCOOP_BUCKETS_DIR}\main"
    $SCOOP_BASE_BUCKET_DIR = "${SCOOP_BUCKETS_DIR}\Base"

    $SCOOP_APP_DIR, $SCOOP_BUCKETS_DIR, $SCOOP_MAIN_BUCKET_DIR, $SCOOP_BASE_BUCKET_DIR | ForEach-Object {
        if (!(Test-Path -LiteralPath $_ -PathType 'Container')) {
            New-Item -Path $_ -ItemType 'Directory' | Out-Null
        }
    }

    if ($INSTALL_USING_GIT) {
        Write-InstallInfo 'Installing using git'
        git clone --branch $SCOOP_BRANCH $SCOOP_GIT_REPO_GIT $SCOOP_APP_DIR

        git clone $SCOOP_MAIN_BUCKET_REPO_GIT $SCOOP_MAIN_BUCKET_DIR
        git clone $SCOOP_BASE_BUCKET_REPO_GIT $SCOOP_BASE_BUCKET_DIR
        return
    }

    $downloader = Get-Downloader

    # 1. download scoop
    $cachedCore = "${INSTALL_CACHE}\Core.zip"
    $scoopZipfile = "${SCOOP_APP_DIR}\Core.zip"
    if (Test-Path -LiteralPath $cachedCore -PathType 'Leaf') {
        Write-InstallInfo "Loading Core from '$cachedCore'"
        Copy-Item $cachedCore $scoopZipfile
    } else {
        Write-InstallInfo 'Downloading Core'
        $downloader.DownloadFile($SCOOP_PACKAGE_REPO, $scoopZipfile)
    }

    # 2. download scoop main bucket
    $cachedMain = "${INSTALL_CACHE}\main.zip"
    $scoopMainZipfile = "${SCOOP_MAIN_BUCKET_DIR}\main.zip"
    if (Test-Path -LiteralPath $cachedMain -PathType 'Leaf') {
        Write-InstallInfo "Loading Main bucket from '$cachedMain'"
        Copy-Item $cachedMain $scoopMainZipfile
    } else {
        Write-InstallInfo 'Downloading Main bucket'
        $downloader.DownloadFile($SCOOP_MAIN_BUCKET_REPO, $scoopMainZipfile)
    }

    # 3. download base bucket
    $cachedBased = "${INSTALL_CACHE}\Base.zip"
    $scoopBaseZipfile = "${SCOOP_BASE_BUCKET_DIR}\Base.zip"
    if (Test-Path -LiteralPath $cachedBased -PathType 'Leaf') {
        Write-InstallInfo "Loading Base bucket from '$cachedBased'"
        Copy-Item $cachedBased $scoopBaseZipfile
    } else {
        Write-InstallInfo 'Downloading Base bucket'
        $downloader.DownloadFile($SCOOP_BASE_BUCKET_REPO, $scoopBaseZipfile)
    }

    # Extract files from downloaded zip
    Write-InstallInfo 'Extracting...'

    #TODO: Move instead of Copy
    # 1. extract scoop
    $scoopUnzipTempDir = "${SCOOP_APP_DIR}\_tmp"
    Expand-ZipArchive $scoopZipfile $scoopUnzipTempDir
    Copy-Item "${scoopUnzipTempDir}\${SCOOP_PACKAGE_REPO_ARCHIVE_NAME}-${SCOOP_BRANCH}\*" $SCOOP_APP_DIR -Recurse -Force

    # 2. extract scoop main bucket
    $scoopMainUnzipTempDir = "${SCOOP_MAIN_BUCKET_DIR}\_tmp"
    Expand-ZipArchive $scoopMainZipfile $scoopMainUnzipTempDir
    Copy-Item "${scoopMainUnzipTempDir}\Main-*\*" $SCOOP_MAIN_BUCKET_DIR -Recurse -Force

    # 3. extract base bucket
    $scoopBaseUnzipTempDir = "${SCOOP_BASE_BUCKET_DIR}\_tmp"
    Expand-ZipArchive $scoopBaseZipfile $scoopBaseUnzipTempDir
    Copy-Item "${scoopBaseUnzipTempDir}\Base-*\*" $SCOOP_BASE_BUCKET_DIR -Recurse -Force

    # Cleanup
    Remove-Item $scoopUnzipTempDir, $scoopMainUnzipTempDir, $scoopBaseUnzipTempDir -Recurse -Force
    Remove-Item $scoopZipfile, $scoopMainZipfile, $scoopBaseZipfile
}

function Install-Scoop {
    Write-InstallInfo 'Initializing...'
    # Validate install parameters
    Test-ValidateParameter
    # Check prerequisites
    Test-Prerequisite
    # Enable TLS 1.2
    Optimize-SecurityProtocol

    # Prepare all the needed files. Download and extract/pull
    Get-AllRequiredFile

    # Create the scoop shim
    Import-ScoopShim

    # Finially ensure scoop shims is in the PATH
    Add-ShimsDirToPath
    # Setup initial configuration of Scoop
    Add-DefaultConfig

    Write-InstallInfo 'Scoop was installed successfully!' -ForegroundColor 'DarkGreen'
    Write-InstallInfo 'Type ''scoop help'' for instructions.'
    Write-InstallInfo 'For the most optimal experience you should use PowerShell Core (7+).'
}
#endregion Functions

#region Main
# Installer script root
$INSTALLER_DIR = $PSScriptRoot
$NoProxy, $Proxy, $ProxyCredential, $ProxyUseDefaultCredentials, $RunAsAdmin, $SkipRobocopy, $INSTALLER_DIR | Out-Null

if (!$env:USERPROFILE) {
    if (!$env:HOME) { Deny-Install 'Cannot resolve user''s home directory. USERPROFILE and HOME environment variables are not set.' }

    $env:USERPROFILE = $env:HOME
}

# Prepare variables
$IS_EXECUTED_FROM_IEX = ($null -eq $MyInvocation.MyCommand.Path)

$SCOOP_DEFAULT_DIR = "${env:USERPROFILE}\Shovel"
$SCOOP_GLOBAL_DEFAULT_DIR = "${env:ProgramData}\Shovel"

# TODO: Change and rebrand
# Scoop repository
$SCOOP_REPO = _firstNonNullOrEmpty $ScoopRepo, $env:SCOOP_REPO, 'https://github.com/Ash258/Scoop-Core'
$SCOOP_REPO = $SCOOP_REPO -replace '\.git$'
# Scoop branch
$SCOOP_BRANCH = _firstNonNullOrEmpty $ScoopBranch, $env:SCOOP_BRANCH, 'main'
# Scoop root directory
$SCOOP_DIR = _firstNonNullOrEmpty $ScoopDir, $env:SCOOP, $SCOOP_DEFAULT_DIR
# Scoop global apps directory
$SCOOP_GLOBAL_DIR = _firstNonNullOrEmpty $ScoopGlobalDir, $env:SCOOP_GLOBAL, $SCOOP_GLOBAL_DEFAULT_DIR
# Scoop cache directory
$SCOOP_CACHE_DIR = _firstNonNullOrEmpty $ScoopCacheDir, $env:SCOOP_CACHE, "${SCOOP_DIR}\cache"
# Scoop shims directory
$SCOOP_SHIMS_DIR = "${SCOOP_DIR}\shims"
# Scoop global shims directory
$SCOOP_GLOBAL_SHIMS_DIR = "${SCOOP_GLOBAL_DIR}\shims"
# Scoop itself directory
$SCOOP_APP_DIR = "${SCOOP_DIR}\apps\scoop\current"
# Scoop buckets directory
$SCOOP_BUCKETS_DIR = "${SCOOP_DIR}\buckets"
# Scoop config file location
$SCOOP_CONFIG_HOME = _firstNonNullOrEmpty $env:XDG_CONFIG_HOME, "${env:USERPROFILE}\.config"
$SCOOP_CONFIG_FILE = "${SCOOP_CONFIG_HOME}\scoop\config.json"

# Cache used for loading the repository zips instead of downloading them.
$INSTALL_CACHE = _firstNonNullOrEmpty $InstallerCacheDir, $ScoopCacheDir

$SCOOP_PACKAGE_REPO_GIT = $SCOOP_REPO
$SCOOP_PACKAGE_REPO = "${SCOOP_PACKAGE_REPO_GIT}/archive/${SCOOP_BRANCH}.zip"
$SCOOP_PACKAGE_REPO_ARCHIVE_NAME = ($SCOOP_REPO -split '/')[-1]
$SCOOP_MAIN_BUCKET_REPO_GIT = 'https://github.com/ScoopInstaller/Main'
$SCOOP_MAIN_BUCKET_REPO = "${SCOOP_MAIN_BUCKET_REPO_GIT}/archive/master.zip"
$SCOOP_BASE_BUCKET_REPO_GIT = 'https://github.com/shovel-org/Base'
$SCOOP_BASE_BUCKET_REPO = "${SCOOP_BASE_BUCKET_REPO_GIT}/archive/main.zip"

$GIT_INSTALLED = [bool] (Get-Command 'git' -ErrorAction 'SilentlyContinue')
$INSTALL_USING_GIT = $GIT_INSTALLED
if ($SkipGit) { $INSTALL_USING_GIT = $false }

# Bootstrap function
& {
    $ErrorActionPreference = 'Stop'
    Install-Scoop
}
#endregion Main
