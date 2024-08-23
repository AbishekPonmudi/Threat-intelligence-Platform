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
