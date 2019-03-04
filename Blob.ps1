# add necessary assembly
#
Add-Type -AssemblyName System.Web

# generate authorization key
Function Generate-MasterKeyAuthorizationSignature
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)][String]$verb,
		[Parameter(Mandatory=$true)][String]$resourceLink,
		[Parameter(Mandatory=$true)][String]$resourceType,
		[Parameter(Mandatory=$true)][String]$dateTime,
		[Parameter(Mandatory=$true)][String]$key,
		[Parameter(Mandatory=$true)][String]$keyType,
		[Parameter(Mandatory=$true)][String]$tokenVersion
	)

	$hmacSha256 = New-Object System.Security.Cryptography.HMACSHA256
	$hmacSha256.Key = [System.Convert]::FromBase64String($key)

	$payLoad = "$($verb.ToLowerInvariant())`n$($resourceType.ToLowerInvariant())`n$resourceLink`n$($dateTime.ToLowerInvariant())`n`n"
	$hashPayLoad = $hmacSha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payLoad))
	$signature = [System.Convert]::ToBase64String($hashPayLoad);

	[System.Web.HttpUtility]::UrlEncode("type=$keyType&ver=$tokenVersion&sig=$signature")
}

# query
Function Query-CosmosDb
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)][String]$EndPoint,
		[Parameter(Mandatory=$true)][String]$DataBaseId,
		[Parameter(Mandatory=$true)][String]$CollectionId,
		[Parameter(Mandatory=$true)][String]$MasterKey,
		[Parameter(Mandatory=$true)][String]$Query
	)

	$Verb = "POST"
	$ResourceType = "docs";
	$ResourceLink = "dbs/$DatabaseId/colls/$CollectionId"

	$dateTime = [DateTime]::UtcNow.ToString("r")
	$authHeader = Generate-MasterKeyAuthorizationSignature -verb $Verb -resourceLink $ResourceLink -resourceType $ResourceType -key $MasterKey -keyType "master" -tokenVersion "1.0" -dateTime $dateTime
	$queryJson = @{query=$Query} | ConvertTo-Json
	$header = @{authorization=$authHeader;"x-ms-documentdb-isquery"="True";"x-ms-version"="2017-02-22";"x-ms-date"=$dateTime}
	$contentType= "application/query+json"
	$queryUri = "$EndPoint$ResourceLink/docs"

	$result = Invoke-RestMethod -Method $Verb -ContentType $contentType -Uri $queryUri -Headers $header -Body $queryJson

	$result | ConvertTo-Json -Depth 10
}

function GetAuthSignedStringSa
 {
     param
     (
         [Parameter(Mandatory=$true)]
         [string]$uri,
  
         [Parameter(Mandatory=$false)]
         [string]$key
     )
  
     # Building Authorization Header for Storage Account
  
     $saName = GetStorageAccountName -uri $uri
     $containerName = GetContainerName -uri $uri
  
     # Time in GMT
     $resourceTz = [System.TimeZoneInfo]::FindSystemTimeZoneById(([System.TimeZoneInfo]::Local).Id)
     [string]$currentDateTimeUtc = Get-Date ([System.TimeZoneInfo]::ConvertTimeToUtc((Get-Date).ToString(),$resourceTz)) -Format r
  
     # String to be signed with storage account key
     $signatureSb = New-Object System.Text.StringBuilder
     $null = $signatureSb.Append("GET`n`n`n`n`napplication/xml`n`n`n`n`n`n`nx-ms-date:$currentDateTimeUtc`nx-ms-version:2015-02-21`n/$saName/$containerName")
     
     if ($containerName -ne $null)
     {
         $null = $signatureSb.Append("/")
     }
  
     $restParameters = GetRestApiParameters -uri $uri
  
     if ($restParameters -ne $null)
     {
         foreach ($param in $restParameters)
         {
             $null = $signatureSb.Append("`n$($param.Replace('=',':'))")   
         }
     }
  
     # Signing string with SA key UTF8 enconded with HMAC-SHA256 algorithm
     [byte[]]$singnatureStringByteArray=[Text.Encoding]::UTF8.GetBytes($signatureSb.ToString())
     $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
     $hmacsha.key = [convert]::FromBase64String($key)
     $signature = [Convert]::ToBase64String($hmacsha.ComputeHash($singnatureStringByteArray))
  
     return  @{
         'x-ms-date'="$currentDateTimeUtc"
         'Content-Type'='application\xml'
         'Authorization'= "SharedKey $saName`:$signature"
         'x-ms-version'='2015-02-21'
     }
 }

Function Get-BlobContainer
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)][String]$EndPoint,
		[Parameter(Mandatory=$true)][String]$MasterKey
	)

	$Verb = "GET"
	$ResourceType = "docs";
	$ResourceLink = "dbs/$DatabaseId/colls/$CollectionId"

	$dateTime = [DateTime]::UtcNow.ToString("r")
	$authHeader = Generate-MasterKeyAuthorizationSignature -verb $Verb -resourceLink $ResourceLink -resourceType $ResourceType -key $MasterKey -keyType "master" -tokenVersion "1.0" -dateTime $dateTime
	$queryJson = @{query=$Query} | ConvertTo-Json
	$header = @{authorization=$authHeader;"x-ms-documentdb-isquery"="True";"x-ms-version"="2017-02-22";"x-ms-date"=$dateTime}
	$contentType= "application/query+json"
	$queryUri = "$EndPoint$ResourceLink/docs"

	$result = Invoke-RestMethod -Method $Verb -ContentType $contentType -Uri $queryUri -Headers $header -Body $queryJson

	$result | ConvertTo-Json -Depth 10
}

# fill the target cosmos database endpoint uri, database id, collection id and masterkey
$CosmosDBEndPoint = "https://salononblob.blob.core.windows.net/?comp=list"

$MasterKey = Get-Content .\keys.txt


$bios = Get-WmiObject Win32_Bios
$model = Get-WmiObject Win32_Computersystem

$jsonRequest = @{
    id= "$($bios.SerialNumber)"
    model = "$($model.Model)"
    biosversion = "$($bios.SMBIOSBIOSVersion)"
}


Get-BlobContainer -EndPoint $CosmosDBEndPoint -MasterKey $MasterKey
