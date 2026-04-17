# Set OpenSSL path
$opensslPath = "D:\OpenSSL\OpenSSL-Win64\bin\openssl.exe"

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "NexusCloud - Setup" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# ======================== CREATE CERTS ========================

Write-Host "Creating SSL certificates..." -ForegroundColor Cyan

$certDir = ".\certs"
$certFile = "$certDir\server.crt"
$keyFile = "$certDir\server.key"

if (!(Test-Path $certDir)) {
    New-Item -ItemType Directory -Path $certDir | Out-Null
}

if ((Test-Path $certFile) -and (Test-Path $keyFile)) {
    Write-Host "OK: Certificates already exist`n" -ForegroundColor Green
}
else {
    # Check OpenSSL exists
    if (!(Test-Path $opensslPath)) {
        Write-Host "ERROR: OpenSSL not found at $opensslPath`n" -ForegroundColor Red
        exit 1
    }

    # Generate self-signed certificate
    & $opensslPath req -x509 -newkey rsa:4096 `
        -keyout $keyFile `
        -out $certFile `
        -days 365 `
        -nodes `
        -subj "/C=RU/ST=Russia/L=Moscow/O=NexusCloud/CN=localhost" 2>$null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "OK: Certificates created`n" -ForegroundColor Green
    }
    else {
        Write-Host "ERROR: Failed to generate certificates!`n" -ForegroundColor Red
        exit 1
    }
}

# ======================== CREATE .ENV ========================

Write-Host "Creating .env configuration..." -ForegroundColor Cyan

$envFile = ".\.env"

if (Test-Path $envFile) {
    Write-Host "OK: .env already exists`n" -ForegroundColor Green
}
else {
    # Generate random password
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    $adminPassword = ([Convert]::ToBase64String($bytes) -replace "[+/=]", "").Substring(0, 25)

    $envContent = @"
# Admin User
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$adminPassword

# Server
HTTP_PORT=8080
HTTPS_PORT=8443
ENABLE_HTTPS=true
CERT_FILE=./certs/server.crt
KEY_FILE=./certs/server.key

# Storage
STORAGE_PATH=./data/storage
MAX_FILE_SIZE=107374182400

# Database
DB_PATH=./data/db/nexus.db

# Security
SESSION_EXPIRY=24h
MAX_LOGIN_ATTEMPTS=5

# SMB/CIFS (Windows)
SMB_ENABLED=true
SMB_PORT=445

# NFS (Linux)
NFS_ENABLED=false
NFS_PORT=2049
"@

    Set-Content -Path $envFile -Value $envContent
    Write-Host "OK: .env created" -ForegroundColor Green
    Write-Host "`n  Admin password: $adminPassword" -ForegroundColor Yellow
    Write-Host "  (also saved in .env file)`n" -ForegroundColor Yellow
}

# ======================== CREATE DATA DIRECTORIES ========================

Write-Host "Creating data directories..." -ForegroundColor Cyan

$dirs = @(
    ".\data",
    ".\data\storage",
    ".\data\db"
)

foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "  Created: $dir" -ForegroundColor Green
    }
}

Write-Host ""

# ======================== DONE ========================

Write-Host "========================================================" -ForegroundColor Green
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  docker build -t nexus-cloud:latest ." -ForegroundColor White
Write-Host "  docker-compose up -d" -ForegroundColor White
Write-Host "  https://localhost:8443" -ForegroundColor White
Write-Host ""
