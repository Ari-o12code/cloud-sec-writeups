# Reading S3 Files Encrypted with Customer Managed KMS Keys Needs Two Permissions

*Tested 26 October 2026 in us-east-1, with the AWS CLI in CloudShell.*

Encryption at rest only stops a reader when opening the file needs a second permission. This test shows when S3 gives you that second check, and what CloudTrail records when the check says no.

## Set Up Two Buckets

I put the same fake KYC file in two buckets. It holds a customer ID, a name and a BVN. The first bucket uses the default encryption, SSE-S3. The second uses SSE-KMS with a customer managed key, and S3 Bucket Key is off.

I created the key and its alias as my admin user:

```bash
aws kms create-key --region us-east-1 --description "kms-lab: SSE-KMS writeup"
aws kms create-alias --region us-east-1 --alias-name alias/kms-lab --target-key-id <key-id>
```

The key has the default key policy. That policy gives the account root `kms:*`, so IAM policies decide who may use the key.

Then I pointed the KMS bucket at that key, with Bucket Key off:

```bash
aws s3api put-bucket-encryption --bucket kmslab-ssekms-<suffix> --region us-east-1 \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"},"BucketKeyEnabled":false}]}'
```

The reader role is called `kms-lab-reader`. Its one inline policy allows `s3:ListBucket` and `s3:GetObject` on both buckets, and nothing else, so it has no KMS permission at all. That is the position a leaked credential or an over-scoped service role puts an attacker in. The role trusts the account, and I assumed it from my admin user with the session name `lab01`. Its policy is in [`policies/reader-policy.json`](policies/reader-policy.json) and its trust policy in [`policies/trust-policy.json`](policies/trust-policy.json).

## Read Both Files as the Role

As that role, I read the SSE-S3 file first:

```bash
aws s3 cp s3://kmslab-sses3-<suffix>/kyc-sample.csv -
```

It printed the file with no error. I didn't save that output. Under SSE-S3, `s3:GetObject` is the only permission that matters.

Then I read the SSE-KMS file, with the same role and the same permissions:

```bash
aws s3 cp s3://kmslab-ssekms-<suffix>/kyc-sample.csv -
```

This time it failed:

```
download failed: s3://kmslab-ssekms-<suffix>/kyc-sample.csv to - An error occurred (AccessDenied)
when calling the GetObject operation: User: arn:aws:sts::111122223333:assumed-role/kms-lab-reader/lab01
is not authorized to perform: kms:Decrypt on resource:
arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
because no identity-based policy allows the kms:Decrypt action
```

S3 allowed the read and KMS refused it.

Next I gave the role one more statement. It allows `kms:Decrypt` on that key, but only when the call comes through S3 in us-east-1. It is in [`policies/decrypt-via-s3.json`](policies/decrypt-via-s3.json), and the Lock Decrypt to S3 section explains it. I ran the same read again and the file printed.

## Find What CloudTrail Kept

These events come from CloudTrail Event history in us-east-1. The trimmed JSON is in [`evidence/`](evidence/).

| UTC, 26 Oct | Event | Identity | Result | Encryption context |
|---|---|---|---|---|
| 18:40:57 | `GenerateDataKey` | `user/iamadmin` (MFA) | allowed | `kmslab-ssekms-<suffix>/kyc-sample.csv` |
| 18:46:44 | `Decrypt`, two events | `assumed-role/kms-lab-reader/lab01` | **AccessDenied** | none recorded |
| 18:48:55 | `Decrypt`, two events | `assumed-role/kms-lab-reader/lab01` | allowed | `kmslab-ssekms-<suffix>/kyc-sample.csv` |

Every one of these events has `invokedBy` and `sourceIPAddress` set to `fas.s3.amazonaws.com`. Neither the role nor my admin user called KMS directly. S3 called KMS for them, through a forward access session. AWS still checks the original caller on both services, so the read only works if the identity can read the object and use the key. AWS explains this in its page on [forward access sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_forward_access_sessions.html).

Three things a responder would want are missing from these events:

- The object read itself. A lookup for `GetObject` over the same window returned `0`, because object reads are S3 data events. Event history holds management events only, and data events need a trail set up to record them.
- The caller's IP address. The KMS events show `fas.s3.amazonaws.com` as the source, not the address the request came from. To find who was reading, you need the S3 data event for the same request.
- The file the denied request wanted. The denied `Decrypt` has `requestParameters: null`, so there is no encryption context. The allowed one names the object. When KMS refuses, it tells you who and which key, but not which file.

The object ARN shows up in the allowed events because Bucket Key was off. With an S3 Bucket Key, S3 uses the bucket ARN as the encryption context, so the KMS events log the bucket instead of the object. In return a Bucket Key cuts KMS request costs by up to 99 percent, according to the [S3 Bucket Keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html) docs. That is a trade between cost and how exactly you can say which file was opened.

**What surprised me.** Each read produced two `Decrypt` events in the same second, with different request IDs, but I ran each read once. I have not found out why yet, so I won't guess here.

## Alert on Denied Decrypts

Alert on a KMS `Decrypt` with `errorCode` `AccessDenied` against a key that guards sensitive data, and name the principal in the alert. One refusal can be a broken job. A role that has never used the key and suddenly tries is worth a look the same day.

Both versions below need a CloudTrail trail, because Event history cannot alert. I have not run them yet.

The first is an EventBridge rule pattern:

```json
{
  "source": ["aws.kms"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["kms.amazonaws.com"],
    "eventName": ["Decrypt"],
    "errorCode": ["AccessDenied"]
  }
}
```

`Decrypt` is a read-only management event, so the rule only matches when its state is `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`. A rule in the plain `ENABLED` state never fires for it, as the [EventBridge docs](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html) explain.

The second is an Athena query over a table built on the trail's logs:

```sql
SELECT eventtime,
       useridentity.arn AS principal,
       useridentity.invokedby AS via,
       errormessage
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname = 'Decrypt'
  AND errorcode = 'AccessDenied'
ORDER BY eventtime DESC;
```

## Lock Decrypt to S3

Two choices keep `s3:GetObject` from being enough to read the file, and they go together.

First, use a customer managed key, not the AWS managed key `aws/s3`. The managed key lets any principal in the account use it through S3, as this [AWS re:Post answer](https://www.repost.aws/questions/QUUFBF6OvvREuaXKzRurcPQA/why-can-s3-access-the-kms-key-resource-under-my-account) explains. So a role with `s3:GetObject` can read the file, and there is no second check. With a customer managed key, decrypt is a separate permission you grant on purpose.

Second, grant `kms:Decrypt` only through S3:

```json
{
  "Sid": "DecryptOnlyThroughS3",
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
  "Condition": { "StringEquals": { "kms:ViaService": "s3.us-east-1.amazonaws.com" } }
}
```

The `kms:ViaService` condition means the role can decrypt only as part of an S3 read. It cannot call `kms:Decrypt` on the key directly.

This does not cover everything. Stolen copies of the role's credentials can still read whatever the S3 grant allows, so keep that grant as narrow as the key grant. And here the default key policy hands the decision to IAM, so anyone who can edit IAM policies can grant decrypt. For real customer data I would name the allowed roles in the key policy itself. Then the key's owner decides who reads, not whoever has IAM write access. That control goes into Terraform when my lab organization starts in November.

## What It Costs a Business

Picture a fintech's KYC bucket under SSE-S3. Any credential with `s3:GetObject` on it can download every customer's ID documents and BVN, whether it belongs to an analytics job or leaked from CI. The business is then left notifying customers and the data protection regulator. Now add a customer managed key, with decrypt granted only to the one service that needs it. The same credential gets AccessDenied, and the refusal sits in CloudTrail with the role's name on it. One key policy turns a breach into a refusal you can alert on.

## What I Would Check Next

I would repeat the reads with S3 data events turned on. That pairs each `Decrypt` with the `GetObject` behind it, shows the caller's real IP, and may show where the second `Decrypt` comes from.
