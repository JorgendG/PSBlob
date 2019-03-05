$accountname="salononblob"
$masterkey = Get-Content .\keys.txt

# generate authorization key
Function Generate-MasterKeyAuthorizationSignature
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)][String]$verb,
		[Parameter(Mandatory=$true)][String]$accountname,
        [Parameter(Mandatory=$false)][String]$container,
        [Parameter(Mandatory=$true)][String]$operation,
		[Parameter(Mandatory=$true)][String]$dateTime,
		[Parameter(Mandatory=$true)][String]$key
	)

	$xmsversion = "2015-02-21"
    if( $container.Length -gt 0 )
    {
        $container = "$container/"
    }

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
                "x-ms-date:$dateTime`nx-ms-version:$xmsversion`n" +     # CanonicalizedHeaders
                "/$accountname/$container`n$operation"       # header 2
    [byte[]]$dataBytes = ([System.Text.Encoding]::UTF8).GetBytes($stringtosign)
    $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha256.Key = [Convert]::FromBase64String($key)
    $sig = [Convert]::ToBase64String($hmacsha256.ComputeHash($dataBytes))
    $authhdr = "SharedKey $accountname`:$sig"
 
    $authhdr
 }



function Get-BlobContainers($accountname, $MasterKey)
{
    $Verb = "GET"
    $dateTime = [DateTime]::UtcNow.ToString("r")
    $EndPoint = "https://$accountname.blob.core.windows.net/?comp=list"

    $authHeader = Generate-MasterKeyAuthorizationSignature -verb $Verb -accountname $accountname -dateTime $dateTime -key $MasterKey -operation "comp:list"

	$header = @{authorization=$authHeader;"x-ms-version"="2015-02-21";"x-ms-date"=$dateTime}
    $result = Invoke-RestMethod -Method $Verb -Uri $EndPoint -Headers $header
    [xml]$responseXml = $result.Substring($result.IndexOf("<"))

    $responseXml.EnumerationResults.Containers.Container
}

function Get-BlobInContainer($accountname, $container, $MasterKey)
{
    $Verb = "GET"
    $dateTime = [DateTime]::UtcNow.ToString("r")
    $EndPoint = "https://$accountname.blob.core.windows.net/$container/?comp=list&restype=container"

    $authHeader = Generate-MasterKeyAuthorizationSignature -verb $Verb -accountname $accountname -dateTime $dateTime -key $MasterKey -container $container -operation "comp:list`nrestype:container"
	$header = @{authorization=$authHeader;"x-ms-version"="2015-02-21";"x-ms-date"=$dateTime}
    $result = Invoke-RestMethod -Method $Verb -Uri $EndPoint -Headers $header
    
    [xml]$responseXml = $result.Substring($result.IndexOf("<"))

    $responseXml.EnumerationResults.Blobs.Blob
}

Get-BlobContainers -accountname $accountname -MasterKey $MasterKey

Get-BlobInContainer -accountname $accountname -container "restblob" -MasterKey $MasterKey