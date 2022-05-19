$log_dir = ".\joint_logs"
$Temp_dir = "c:\temp\elios-impersonation"

$today = Get-Date -Format "yyyy-MM-dd"
$daysback = 1

$Command = "java -jar alfresco-audit-export.jar $($today) $($daysback) $($Temp_dir)"


Write-Host "executing $Command"

$old_location = Get-Location
Set-Location ".\bin"
Invoke-Expression -Command $Command 
Set-Location $old_location



$compress = @{
  Path = "$($Temp_dir)\*.csv", "$($Temp_dir)\*.json"
  CompressionLevel = "Fastest"
  DestinationPath = "$($log_dir)\logs-$($today).zip"
}
Compress-Archive @compress -Force

Remove-Item -LiteralPath $Temp_dir -Force -Recurse