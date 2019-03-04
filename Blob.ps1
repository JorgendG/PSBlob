$accountname="salononblob"
$key = Get-Content .\keys.txt
$verb = "GET"

$RESTAPI_URL = "https://$accountname.blob.core.windows.net/?comp=list"
$date=(Get-Date).ToUniversalTime()
$datestr=$date.ToString("R");
$xmsversion = "2015-02-21"

$stringtosign = "$verb`n" + # verb
                "`n" +     # content encoding
                "`n" +     # content language
                "`n" +     # content length
                "`n" +     # content md5
                "`n" +     # content type
                "`n" +     # date
                "`n" +     # if modified since
                "`n" +     # if match
                "`n" +     # if none match
                "`n" +     # if unmodified since
                "`n" +     # range
                "x-ms-date:$datestr`nx-ms-version:$xmsversion`n" +     # CanonicalizedHeaders
                "/$accountname/`ncomp:list"       # header 2
 

[byte[]]$dataBytes = ([System.Text.Encoding]::UTF8).GetBytes($stringtosign)
$hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
$hmacsha256.Key = [Convert]::FromBase64String($key)
$sig = [Convert]::ToBase64String($hmacsha256.ComputeHash($dataBytes))
$authhdr = "SharedKey $accountname`:$sig"
 
write-host $authhdr
 
$RequestHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
 
$RequestHeader.Add("x-ms-version", "$xmsversion")
$RequestHeader.Add("x-ms-date", $datestr) 
$RequestHeader.Add("Authorization", $authhdr)

$x = Invoke-RestMethod -Uri $RESTAPI_URL -Method $verb -Headers $RequestHeader -SessionVariable bla #-ContentType application/json
 
[xml]$responseXml = $x.Substring($x.IndexOf("<"))

$responseXml