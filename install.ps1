# Ensure that PowerShell script execution is enabled
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

$certlocation = "certificate.p12" 

# get the certificate from the location to install on store
$certcommand = Get-PfxCertificate -FilePath $certlocation
Import-pfxCertificate -FilePath $certlocation -CertStoreLocation Cert:\CurrentUser\Root -Exportable
Write-Output " <<<< Certificate intillized on the intermidiate location >>>>"

$thumprint = $certcommand.Thumbprint

function Move-certificatetotrusted {
    param (
        [string]$storelocation,
        [string]$thumprint
    )
    $intermidiatestore = New-Object system.security.cryptography.X509Certificates.X509Store("CA", $storeLocation)
    $intermidiatestore.open("ReadWrite")

    # to find the certification by thumprint
    $cert = $intermidiatestore.certificates | Where-Object { $_.Thumbprint -eq $thumprint} 

    # move to trusted from intermidiate path
    if ($cert){
        $trustedrootstore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", $storeLocation)
        $trustedrootstore.open("Readwrite")	
        $trustedrootstore.Add($cert)
        $trustedrootstore.close()
        $intermidiatestore.remove($cert)
        Write-Output " <<<< Certificate installed sucessfully on the trusted sucessfully >>>> "
    }
    else{
        Write-Output " !!!! Certification not found !!!! "
    }
    $intermidiatestore.close()
}

Move-certificatetotrusted -storelocation "CurrentUser" -thumprint $thumprint

# Function to install Scoop
function Install-Scoop {
    if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Scoop..."
        Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
        $scoopPath = "$env:USERPROFILE\scoop\shims"
        [System.Environment]::SetEnvironmentVariable("PATH", "$env:PATH;$scoopPath", [System.EnvironmentVariableTarget]::User)
        Write-Host "Scoop has been installed and added to PATH."
    } else {
        Write-Host "Scoop is already installed."
    }
}

# Function to install YARA using Scoop
function Install-YARA-WithScoop {
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Host "Installing YARA using Scoop..."
        scoop install yara
    } else {
        Write-Host "Scoop is not installed. Skipping YARA installation via Scoop."
    }
}
# Function to install Python libraries
function Install-PythonLibraries {
    Write-Host "Upgrading pip..."
    python -m pip install --upgrade pip

    Write-Host "Installing Python libraries..."
    python -m pip install pefile yara-python pywin32 tqdm psutil pandas yara-python scapy mitmproxy
}

# Function to install Npcap from URL
function Install-Npcap-FromUrl {
    $npcapUrl = "https://npcap.com/dist/npcap-1.79.exe"
    $npcapInstaller = "$env:TEMP\npcap-1.79.exe"
    
    Write-Host "Downloading Npcap..."
    iwr -Uri $npcapUrl -OutFile $npcapInstaller

    Write-Host "Installing Npcap..."
    Start-Process -FilePath $npcapInstaller

    Write-Host "Npcap installation complete."
}
# Function to install mitmproxy from URL
function Install-Mitmproxy-FromUrl {
    $mitmproxyUrl = "https://downloads.mitmproxy.org/10.4.2/mitmproxy-10.4.2-windows-x86_64-installer.exe"
    $mitmproxyInstaller = "$env:TEMP\mitmproxy-10.4.2-windows-x86_64-installer.exe"
    
    Write-Host "Downloading mitmproxy..."
    iwr -Uri $mitmproxyUrl -OutFile $mitmproxyInstaller

    Write-Host "Installing mitmproxy..."
    Start-Process -FilePath $mitmproxyInstaller

    Write-Host "mitmproxy installation complete."
}

Run the functions
Install-Scoop
Install-YARA-WithScoop
Install-PythonLibraries
Install-Npcap-FromUrl
Install-Mitmproxy-FromUrl

Write-Host "Setup complete !! Plese Cold Start Your PC."
Start-sleep -Seconds 2

Exit

# SIG # Begin signature block
# MIIFhQYJKoZIhvcNAQcCoIIFdjCCBXICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+j1dgsbZW9XKXIyVMBplkcK1
# YOygggMYMIIDFDCCAfygAwIBAgIQfwaQ6kcoM5FGEPnTjjO2PjANBgkqhkiG9w0B
# AQUFADAiMSAwHgYDVQQDDBdQb3dlclNoZWxsIENvZGUgU2lnbmluZzAeFw0yNDA4
# MzAwODE3MzNaFw0yNTA4MzAwODM3MzNaMCIxIDAeBgNVBAMMF1Bvd2VyU2hlbGwg
# Q29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvwCZ
# XTGUPhyXmwd+jFFCBy1etbI0blKY0IE3cqLkv0vJ76+566kBQecxVloOO9tTbjLq
# nyLJDAWK0SfV/j7+QYpbBtb4Ic8NwRJFTdWI7YzZRaFXAejwPa1jllorpSOYMLHa
# uM+CKbFK1AFxtij+t1+8u3ZunNbXW/jNm+7lubXr43Nb5uaZgrAs8uJUfNw33cie
# 99umh5N/nQ5Q/p0CrEuPk8xTZ7ITCOnMNaT5pV0/adx3PXBEsdg6PvlHG1fm6wgQ
# IHezr1EPTwNtab5/ZNs3rORQIQ0yByVl2LnGU8++J7QNt0MeRaa4WPvY+zReX2om
# KRZ+Am2/Ouo/bzJkOQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
# CgYIKwYBBQUHAwMwHQYDVR0OBBYEFNrM7x1pa/TGqzQQKN94Efi1NgpfMA0GCSqG
# SIb3DQEBBQUAA4IBAQBtg/0uzuEnCGwGgOrs6JdUUidzYSprUzeiadfotLr9MskH
# 7uLzrkdcxpsOI9E7yFUfBwAz/NI1WJx7Ie8bNS80JCF2xX4iVnXrH7pwPB/4ap4v
# KjB5buoPR5BgygttTk9XWyTNLXgcfYl860iIlNzio0p2dKAiol82xh8MVm/DEYqJ
# hvzGL3tzFjyswtrCCUJC8bOQZj/bSo7Gml0XlVgbmCwbi76aHnIEQ/Hon8Bg0Vi3
# RIRWJgEfILog4DxG+QEEUOH6AHkTdMEdFYsprwaDh9oRgG+tsM7U01zpfhZIdH3/
# yRarDsRQay+EWKYu8BXVXiBVaR0jcyCbEDpL6z76MYIB1zCCAdMCAQEwNjAiMSAw
# HgYDVQQDDBdQb3dlclNoZWxsIENvZGUgU2lnbmluZwIQfwaQ6kcoM5FGEPnTjjO2
# PjAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAjBgkqhkiG9w0BCQQxFgQUeaRZx989AHr7EUg846nti02WLtkwDQYJKoZIhvcN
# AQEBBQAEggEAHDwhtQoA/NSnB7WOlnaZo29gAw28f0Eueoie/tZOVCott/fK15Z3
# Lb2r+2wk7Dw4bvYyY+ujeEzQRh/IS58w7jkVLyOFU9Wn4FUqVkpBfOXk/e+gLAqH
# JXsfkTj7O3IZeiYy2dcNlwy0PT4PedgrQxc7ZS+rwHG19B/xMMZLYAabM/64slz3
# ALGwVABjmKD+3h5YxXjiSwz2BNy1V0vs8IKdd3yncFc7F/9LYzPkUAB/ZNR3C2Wx
# OM26alW1x5RQi31ZG4GEWu1aKnoLLIJ9yQBfvwURtkJweqSa6eGUaYkl7SaiVLoW
# bzdZCnI7QO21uTFCeSCaw8IUnNIvQPAwPg==
# SIG # End signature block
