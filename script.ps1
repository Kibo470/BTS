# === Variables de configuration ===

# Paramètres FTP
$ftpServer = ""             # Adresse du serveur FTP (à remplir par l'utilisateur)
$remoteDirectory = ""       # Répertoire distant (optionnel)
$fileName = ""              # Nom du fichier à télécharger
$localDirectory = ""        # Dossier local où enregistrer le fichier
$username = ""              # Nom d'utilisateur FTP
$password = ""              # Mot de passe FTP

# Paramètres de messagerie (Gmail SMTP) - À remplir par l'utilisateur
$smtpServer = ""            # Serveur SMTP (ex : smtp.gmail.com)
$smtpPort = 587             # Port pour l'envoi sécurisé via TLS (587 par défaut)
$from = ""                  # Adresse e-mail de l'expéditeur
$to = ""                    # Adresse e-mail du destinataire
$mailUsername = ""          # Nom d'utilisateur pour l'authentification Gmail
$mailPassword = ""          # Mot de passe ou mot de passe d'application pour Gmail (à remplir par l'utilisateur)

$subjectSuccess = "Téléchargement FTP réussi"
$subjectFailure = "Échec du téléchargement FTP"

# === Demande d'informations utilisateur ===
# Lecture et validation de l'adresse FTP
do {
    $ftpServer = Read-Host "Entrez l'adresse du serveur FTP (ex: ftp://example.com)"
    if (-not $ftpServer) {
        Write-Host "Erreur : L'adresse du serveur FTP est obligatoire !" -ForegroundColor Red
    } elseif (-not $ftpServer.StartsWith("ftp://")) {
        Write-Host "Erreur : L'adresse du serveur FTP doit commencer par 'ftp://'" -ForegroundColor Red
        $ftpServer = $null
    }
} while (-not $ftpServer)

# Demande du répertoire distant (sur le serveur FTP)
$remoteDirectory = Read-Host "Entrez le dossier distant où se trouve le fichier (ex: /uploads). Laissez vide pour la racine"

$fileName = Read-Host "Entrez le nom du fichier à télécharger (ex: fichier.txt)"
if (-not $fileName) {
    Write-Host "Erreur : Le nom du fichier est obligatoire !" -ForegroundColor Red
    exit
}

$localDirectory = Read-Host "Entrez le dossier local pour enregistrer le fichier (ex: C:\Temp)"
if (-not $localDirectory) {
    Write-Host "Erreur : Le dossier local est obligatoire !" -ForegroundColor Red
    exit
}

$username = Read-Host "Entrez votre nom d'utilisateur FTP"
$password = Read-Host "Entrez votre mot de passe FTP"

$mailUsername = Read-Host "Entrez votre nom d'utilisateur (email) pour l'envoi des notifications"
$mailPassword = Read-Host "Entrez le mot de passe ou le mot de passe d'application pour Gmail" -AsSecureString
$smtpServer = Read-Host "Entrez l'adresse du serveur SMTP (ex: smtp.gmail.com)"
$smtpPort = Read-Host "Entrez le port SMTP (587 pour Gmail, sinon laissez vide pour 587)" 
if (-not $smtpPort) {
    $smtpPort = 587 # Valeur par défaut pour Gmail
}
$from = Read-Host "Entrez l'adresse email de l'expéditeur"
$to = Read-Host "Entrez l'adresse email du destinataire"

# === Fonctions ===

# Fonction pour normaliser les chemins FTP
function Join-PathWithFTP {
    param (
        [string]$ftpServer,
        [string]$remoteDirectory,
        [string]$fileName
    )
    if (-not [string]::IsNullOrWhiteSpace($remoteDirectory)) {
        if (-not $remoteDirectory.StartsWith("/")) { $remoteDirectory = "/$remoteDirectory" }
        if ($remoteDirectory.EndsWith("/")) { $remoteDirectory = $remoteDirectory.TrimEnd("/") }
    } else {
        $remoteDirectory = ""
    }
    return "$ftpServer$remoteDirectory/$fileName"
}

# Fonction pour vérifier si un fichier existe sur le serveur FTP
function Test-FTPFileExists {
    param (
        [string]$ftpServer,
        [string]$remoteDirectory,
        [string]$fileName,
        [string]$username,
        [string]$password
    )
    $ftpUri = Join-PathWithFTP -ftpServer $ftpServer -remoteDirectory $remoteDirectory -fileName $fileName
    Write-Host "URL générée pour la vérification : $ftpUri" -ForegroundColor Yellow

    try {
        $request = [System.Net.FtpWebRequest]::Create($ftpUri)
        $request.Credentials = New-Object System.Net.NetworkCredential($username, $password)
        $request.Method = [System.Net.WebRequestMethods+Ftp]::GetFileSize
        $response = $request.GetResponse()
        $response.Close()
        Write-Host "Le fichier existe sur le serveur FTP : $ftpUri" -ForegroundColor Green
        return $true
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode -eq 550) {
            Write-Host "Erreur : Le fichier n'existe pas sur le serveur FTP : $ftpUri" -ForegroundColor Red
        } else {
            Write-Host "Erreur : Impossible de vérifier l'existence du fichier. $($_.Exception.Message)" -ForegroundColor Red
        }
        return $false
    }
}

# Fonction pour créer un dossier local avec toutes les permissions
function Ensure-LocalDirectory {
    param (
        [string]$localDirectory
    )
    if (-not (Test-Path -Path $localDirectory)) {
        Write-Host "Le dossier $localDirectory n'existe pas. Création en cours..." -ForegroundColor Cyan
        New-Item -ItemType Directory -Path $localDirectory | Out-Null
        Write-Host "Dossier $localDirectory créé avec succès !" -ForegroundColor Green

        # Ajouter les permissions "Full Control" pour tous les utilisateurs
        try {
            icacls $localDirectory /grant Everyone:(F) /t /c | Out-Null
            Write-Host "Permissions 'Full Control' attribuées au dossier $localDirectory pour 'Everyone'." -ForegroundColor Green
        }
        catch {
            Write-Host "Erreur lors de l'attribution des permissions : $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Le dossier $localDirectory existe déjà. Les fichiers seront écrits dedans." -ForegroundColor Yellow
    }
}

# Fonction pour télécharger un fichier depuis le serveur FTP
function Download-FTPFile {
    param (
        [string]$ftpServer,
        [string]$remoteDirectory,
        [string]$fileName,
        [string]$localFilePath,
        [string]$username,
        [string]$password
    )
    $ftpUri = Join-PathWithFTP -ftpServer $ftpServer -remoteDirectory $remoteDirectory -fileName $fileName
    Write-Host "URL générée pour le téléchargement : $ftpUri" -ForegroundColor Yellow

    try {
        $request = [System.Net.FtpWebRequest]::Create($ftpUri)
        $request.Credentials = New-Object System.Net.NetworkCredential($username, $password)
        $request.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile

        # Télécharger et écrire dans le fichier
        $response = $request.GetResponse()
        $responseStream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::Create($localFilePath)

        try {
            Write-Host "Téléchargement en cours de $ftpUri vers $localFilePath..." -ForegroundColor Cyan
            $responseStream.CopyTo($fileStream)
            Write-Host "Téléchargement terminé avec succès !" -ForegroundColor Green
        }
        finally {
            $responseStream.Dispose()
            $fileStream.Dispose()
            $response.Close()
        }
    }
    catch {
        Write-Host "Erreur lors du téléchargement : $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

# Fonction pour envoyer un e-mail de notification via Gmail SMTP
function Send-EmailNotification {
    param (
        [string]$smtpServer,
        [int]$smtpPort,
        [string]$from,
        [string]$to,
        [string]$subject,
        [string]$body,
        [string]$username,
        [SecureString]$password
    )
    try {
        $credential = New-Object System.Management.Automation.PSCredential($username, $password)

        Send-MailMessage -SmtpServer $smtpServer `
                         -Port $smtpPort `
                         -From $from `
                         -To $to `
                         -Subject $subject `
                         -Body $body `
                         -BodyAsHtml `
                         -Credential $credential `
                         -UseSsl

        Write-Host "E-mail envoyé avec succès à $to" -ForegroundColor Green
    }
    catch {
        Write-Host "Erreur lors de l'envoi de l'e-mail : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# === Exemple d'utilisation ===
Write-Host "=== Configuration du téléchargement FTP ===" -ForegroundColor Cyan

Ensure-LocalDirectory -localDirectory $localDirectory
$localFilePath = Join-Path -Path $localDirectory -ChildPath $fileName

if (Test-FTPFileExists -ftpServer $ftpServer -remoteDirectory $remoteDirectory -fileName $fileName -username $username -password $password) {
    try {
        Download-FTPFile -ftpServer $ftpServer -remoteDirectory $remoteDirectory -fileName $fileName -localFilePath $localFilePath -username $username -password $password

        $bodySuccess = @"
Bonjour,

Le fichier `$fileName a été téléchargé avec succès depuis le serveur FTP `$ftpServer/$remoteDirectory dans le dossier `$localDirectory.

Cordialement,
Votre script FTP
"@
        Send-EmailNotification -smtpServer $smtpServer `
                               -smtpPort $smtpPort `
                               -from $from `
                               -to $to `
                               -subject $subjectSuccess `
                               -body $bodySuccess `
                               -username $mailUsername `
                               -password $mailPassword
    }
    catch {
        $bodyFailure = @"
Bonjour,

Une erreur est survenue lors du téléchargement du fichier `$fileName depuis le serveur FTP `$ftpServer/$remoteDirectory.

Cordialement,
Votre script FTP
"@
        Send-EmailNotification -smtpServer $smtpServer `
                               -smtpPort $smtpPort `
                               -from $from `
                               -to $to `
                               -subject $subjectFailure `
                               -body $bodyFailure `
                               -username $mailUsername `
                               -password $mailPassword
    }
}
