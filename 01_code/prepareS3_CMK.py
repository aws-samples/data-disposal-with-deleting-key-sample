#!/usr/bin/env python3

import json
import boto3
import argparse

# define 'CustomKeyStoreId' to create Key into CloudHSM
customKeyStoreId='cks-017bddc662b70961d'

# create Keys managed with using KMS into KMS
def createCMK_KMS(keyName):
    
    client = boto3.client("kms", region_name="us-east-1")

    # create key into KMS
    key=client.create_key(
        KeyUsage='ENCRYPT_DECRYPT',
        CustomerMasterKeySpec='SYMMETRIC_DEFAULT',
        Origin='AWS_KMS'
    )
    keyid=key['KeyMetadata']['KeyId']
    print("keyid : "+keyid)
    
    # create alias to concern to the key
    client.create_alias(
        AliasName="alias/"+keyName,
        TargetKeyId=keyid
    )
    print("keyName : "+keyName+"(keyid : "+keyid+")")
    
    return keyid

# create Keys managed with using KMS into CloudHSM
def createCMK_CloudHSM(keyName):
    
    client = boto3.client("kms", region_name="us-east-1")

    # create key into CloudHSM
    key=client.create_key(
        KeyUsage='ENCRYPT_DECRYPT',
        CustomerMasterKeySpec='SYMMETRIC_DEFAULT',
        Origin='AWS_CLOUDHSM',
        CustomKeyStoreId=customKeyStoreId
    )

    keyid=key['KeyMetadata']['KeyId']
    print("keyid : "+keyid)
    
    # create alias to concern to the key
    client.create_alias(
        AliasName="alias/"+keyName,
        TargetKeyId=keyid
    )
    print("keyName : "+keyName+"(keyid : "+keyid+")")

    return keyid


# create S3 bucket
def createBucket(backetName):

    client = boto3.client('s3')

    response = client.create_bucket(
        ACL='private',
        Bucket=backetName,
        ObjectLockEnabledForBucket=True
    )
    client.put_public_access_block(
        Bucket=backetName,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    return response
    

# create files to upload S3 bucket as objects
def createOjectFiles(files):

    for i in range(5):
        file_name = files[i]

        # object fileの作成
        with open("./tmp/" + file_name, 'w') as f:
            f.write(file_name)

# upload objects with each encrypting option
def uploadOjectFiles(files,ExtraArgs,BucketName):

    for i in range(5):
        file_name = files[i]

        response = boto3.client('s3').upload_file(
            Filename='./tmp/' + file_name,
            Bucket=BucketName,
            Key=file_name,
            ExtraArgs=ExtraArgs[i]
            #ExtraArgs={'ServerSideEncryption': 'AES256'}
        )

    return


def main():

    parser = argparse.ArgumentParser(description='create S3, KMS-CMK')
    parser.add_argument('-b','--backetName', metavar='backetName', type=str, nargs=1,default=["dsd-backet-20200529r09"],help='target backet name')
    parser.add_argument('-k','--keyName', metavar='keyName', type=str, nargs=1,help='name of CMK : for ex. dsd-cmk-2020mmddr**', required=True)

    args = parser.parse_args()
    
    BucketName=args.backetName[0]
    print("backet name : ",BucketName)

    KeyNameKMS=args.keyName[0]+"-kms"
    KeyNameCloudHSM=args.keyName[0]+"-cloudhsm"
    print("name of CMK into KMS : ",KeyNameKMS)
    print("name of CMK into CloudHSM: ",KeyNameCloudHSM)

    keyidKMS=createCMK_KMS(KeyNameKMS)
    keyidCloudHSM=createCMK_CloudHSM(KeyNameCloudHSM)

    print("keyid in KMS: "+ keyidKMS)
    print("keyid in CloudHSM: "+ keyidCloudHSM)

    response = createBucket(BucketName)

    files = ["S3Master.dat","KMS_S3.dat","KMS_CMKinKMS.dat","KMS_CMKinCloudHSM.dat","nonencryption.dat"]
    ExtraArgs = [
        {
            'ServerSideEncryption': 'AES256'
        },
        {
            'ServerSideEncryption': 'aws:kms'
        },
        {
            'ServerSideEncryption': 'aws:kms',
            'SSEKMSKeyId': keyidKMS
        },
        {
            'ServerSideEncryption': 'aws:kms',
            'SSEKMSKeyId': keyidCloudHSM
        },
        {}
    ]
    createOjectFiles(files)
    uploadOjectFiles(files,ExtraArgs,BucketName)


# main
if __name__ == "__main__":
    main()
