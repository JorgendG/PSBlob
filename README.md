# PSBlob
Powershell and Blob storage using RESTapi

Change these variables to make it work for your account.
```
$accountname = "yourblobaccountname"
$masterkey = Get-Content .\keys.txt
```
The keys.txt is a textfile containing the access key.

This script use the REST api to interact with Blob object.

I've created/copied/modified 3 functions.
- Generate-MasterKeyAuthorizationSignature
- Get-BlobContainers
- Get-BlobInContainer


```
Get-BlobContainers -accountname $accountname -MasterKey $MasterKey


Name     Properties
----     ----------
blob2    Properties
restblob Properties
```
