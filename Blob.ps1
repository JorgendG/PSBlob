# Define a class
class RestBlob
{
    [string] $AccountName
    [string] $MasterKey
    hidden [string] $xmlversion = "2015-02-21"

    # Constructor
    RestBlob ([string] $accountname, [string] $MasterKey)
    {
        $this.AccountName = $accountname
        $this.MasterKey = $MasterKey
    }

    hidden [string] NewMasterKeyAuthorizationSignature( [string] $verb, [string]$container, [string]$filename, [string] $operation, [string]$dateTime)
    {
        $filelength = ""
        $blobtype = ""
        if( $container.Length -gt 0 )
        {
            $container = "$container/"
            if( $filename )
            {
                if( $verb -ne 'GET')
                {
                    $container = "$container$((Get-ChildItem -File $filename).Name)"
                    $filelength = (Get-ChildItem -File $filename).Length
                }
                else {
                    $container = "$container$filename"    
                }
                $blobtype = "x-ms-blob-type:BlockBlob`n"
            }
        }
        if( $operation)
        {
            $operation = "`n$operation"
        }

        $stringtosign = "$verb`n" + # verb
                    "`n" +     # content encoding
                    "`n" +     # content language
                    "$filelength`n" +     # content length
                    "`n" +     # content md5
                    "`n" +     # content type
                    "`n" +     # date
                    "`n" +     # if modified since
                    "`n" +     # if match
                    "`n" +     # if none match
                    "`n" +     # if unmodified since
                    "`n" +     # range
                    "$($blobtype)x-ms-date:$dateTime`nx-ms-version:$($this.xmlversion)`n" +     # CanonicalizedHeaders
                    "/$($this.accountname)/$container$operation"       # header 2
        [byte[]]$dataBytes = ([System.Text.Encoding]::UTF8).GetBytes($stringtosign)
        $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha256.Key = [Convert]::FromBase64String($this.MasterKey)
        $sig = [Convert]::ToBase64String($hmacsha256.ComputeHash($dataBytes))
        $authhdr = "SharedKey $($this.AccountName)`:$sig"
    
        return $authhdr
    }

    [string[]]ListContainers()
    {
        $Verb = "GET"
        $dateTime = [DateTime]::UtcNow.ToString("r")
        $EndPoint = "https://$($this.accountname).blob.core.windows.net/?comp=list"

        $authHeader = $this.NewMasterKeyAuthorizationSignature( $Verb, "", "", "comp:list", $dateTime )

        $header = @{authorization=$authHeader;"x-ms-version"=$this.xmlversion;"x-ms-date"=$dateTime}
        $result = Invoke-RestMethod -Method $Verb -Uri $EndPoint -Headers $header
        [xml]$responseXml = $result.Substring($result.IndexOf("<"))

        return ($responseXml.EnumerationResults.Containers.Container | Select-Object -ExpandProperty name )
    }

    [string[]]ListBlobs( [string] $container)
    {
        $Verb = "GET"
        $dateTime = [DateTime]::UtcNow.ToString("r")
        $EndPoint = "https://$($this.AccountName).blob.core.windows.net/$container/?comp=list&restype=container"

        $authHeader = $this.NewMasterKeyAuthorizationSignature( $Verb, $container, "", "comp:list`nrestype:container", $dateTime )

        $header = @{authorization=$authHeader;"x-ms-version"=$this.xmlversion;"x-ms-date"=$dateTime}
        $result = Invoke-RestMethod -Method $Verb -Uri $EndPoint -Headers $header
        [xml]$responseXml = $result.Substring($result.IndexOf("<"))

        return ($responseXml.EnumerationResults.Blobs.Blob | Select-Object -ExpandProperty name )
    }

    [void]NewBlob( $container, $filename)
    {
        $Verb = "PUT"
        $dateTime = [DateTime]::UtcNow.ToString("r")
        $EndPoint = "https://$($this.AccountName).blob.core.windows.net/$container/$((Get-ChildItem -File $filename).Name)"

        $authHeader = $this.NewMasterKeyAuthorizationSignature( $Verb, $container, $filename, "", $dateTime )
        $header = @{authorization=$authHeader;"x-ms-version"=$this.xmlversion;"x-ms-date"=$dateTime;"x-ms-blob-type"="BlockBlob"}
        Invoke-RestMethod -Method $Verb -Uri $EndPoint -Headers $header -InFile $filename
    }

    [void]GetBlob($container, $filename)
    {
        $Verb = "GET"
        $dateTime = [DateTime]::UtcNow.ToString("r")
        
        $EndPoint = "https://$($this.accountname).blob.core.windows.net/$container/$(($filename -split '\\')[-1])"

        $authHeader = $this.NewMasterKeyAuthorizationSignature( $Verb, $container, ($filename -split '\\')[-1], "", $dateTime )
        $header = @{authorization=$authHeader;"x-ms-version"=$this.xmlversion;"x-ms-date"=$dateTime;"x-ms-blob-type"="BlockBlob"}
        Invoke-RestMethod -Method $Verb -Uri $EndPoint -Headers $header -OutFile $filename
    }
}


$masterkey = (Get-Content .\keys.txt)[0]
$accountname=(Get-Content .\keys.txt)[1]

$a = New-Object RestBlob( $accountname, $masterkey)
$a.ListContainers()
$a.ListBlobs( 'restblob' )
$a.ListBlobs( 'blob2' )
$a.NewBlob( 'blob2', 'C:\temp\test2.txt' )
$a.GetBlob( 'blob2', 'C:\temp\test2.txt' )