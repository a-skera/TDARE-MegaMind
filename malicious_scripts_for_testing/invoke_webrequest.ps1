# Test URL (localhost is safe so we use it) but if you want to reach a C2 it's up tp you (For Edu and test only)
$testUrl = "http://localhost:8080"  

try {
    $response = Invoke-WebRequest -Uri $testUrl -UseBasicParsing
    Write-Host "Request sent. Status Code:" $response.StatusCode
} catch {
    Write-Host "Request failed (expected if no server is running)"
}
