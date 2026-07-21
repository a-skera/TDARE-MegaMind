# ============================================================
#  EDUCATIONAL MALWARE SCRIPT – FOR TRAINING ONLY 
#  This script does NOT harm the system.
#  It is intentionally suspicious to TEST reverse engineering.
# ============================================================

# ---- Obfuscated Author ----
$creator = "VGRhcmUgVGVzdCBNYWx3YXJl"   # Base64: "TDare Test Malware"
$creatorDecoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($creator))

# ---- Fake Payload in Base64 (just text) ----
$fakePayload = "U2FmZSBTY3JpcHQgZm9yIFJE"  # Base64: "Safe Script for RE"
$decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($fakePayload))

# ---- Suspicious Indicators on Purpose ----
function Invoke-Secret {
    param([string]$c)
    Write-Host "Executing hidden command..."  # In real malware this is dangerous!
    # But here it only prints
    Write-Output ("You passed: " + $c)
}

# ---- Looks like fileless execution (but it is fake) ----
$commandEncoded = "SW52b2tlLVByb2Nlc3MgZWNobyAiVGhpczogRmFrZSBNYWx3YXJlIFNjcmlwdCI="
$decodedCmd     = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($commandEncoded))
Invoke-Secret $decodedCmd

# ---- Fake C2 Server (Just Text) ----
$C2 = "hxxp://evil-server[.]com/api"    # Use hxxp to keep it SAFE
Write-Host "`n[!] Possible C2 Communication to: $C2"

# ---- Suspicious Function Names ----
function Start-StealthMode { Write-Host "Stealth mode activated (just text)." }
function Get-Credentials { Write-Host "[!] Would steal credentials... but here it does nothing." }
function Hide-Window { Write-Host "Window hidden (in real malware)." }

# ---- Simulate Execution Flow ----
Hide-Window
Start-StealthMode
Get-Credentials

Write-Host "`n----- SUMMARY -----"
Write-Host "Decoded Author  : $creatorDecoded"
Write-Host "Payload Content : $decodedPayload"
Write-Host "Command Sent    : $decodedCmd"
Write-Host "NOTE: No real malicious actions executed."
