# Test URL (localhost is safe)
$testUrl = "http://localhost:8080"  

try {
    $response = Invoke-WebRequest -Uri $testUrl -UseBasicParsing
    Write-Host "Request sent. Status Code:" $response.StatusCode
} catch {
    Write-Host "Request failed (expected if no server is running)"
}
