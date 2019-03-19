# PSBlob
Powershell and Blob storage using RESTapi

Create a keys.txt file to make it for for your account.
First line contains the access key, the second line the accountname.
```
$masterkey = (Get-Content .\keys.txt)[0]
$accountname=(Get-Content .\keys.txt)[1]
```

This script use the REST api to interact with Blob object.

I've created/copied/modified 3 functions.
- Generate-MasterKeyAuthorizationSignature
- Get-BlobContainers
- Get-BlobInContainer


```
$accountname="myaccount"
$masterkey = Get-Content .\keys.txt

$a = New-Object RestBlob( $accountname, $masterkey)
$a.ListContainers()
$a.ListBlobs( 'restblob' )
$a.ListBlobs( 'blob2' )
$a.NewBlob( 'blob2', 'C:\temp\test2.txt' )
$a.GetBlob( 'blob2', 'C:\temp\test2.txt' )
```
