import json
import boto3
import argparse
import logging
import csv
import base64
import hashlib

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# the parameter of KMS to sign output file
SigningAlgorithm='ECDSA_SHA_256'

# define resource of S3
s3_resource = boto3.resource('s3')

# define client of KMS
kms_client = boto3.client('kms', region_name="us-east-1")

# define the directory to store temporary output files
# !! it needs the usage of temp directory for lambda function!!
tmpDir="/tmp/"

# main workload to delete S3 bucket named as "bucketName" and all keys
#  bucketName : the target bucket name to delete
#  filenameOfKeyList : define the filename for the file about key information
#  digestFilePath : the filename of digest for signature
#  signatureFilePath : the filename of signature
#  bucketNameStoredKeylist : the bucket name stored the file of key information and signature
#  KeyIdToSign : Key ID to sign at thekey list file
def delStorageData(
        bucketName,
        filenameOfKeyList,
        digestFilePath,
        signatureFilePath,
        bucketNameStoredKeylist,
        keyIdToSign
    ):

    
    try:
        # define and check existance of resources
        s3_resource.meta.client.head_bucket(Bucket=bucketName)
        s3_resource.meta.client.head_bucket(Bucket=bucketNameStoredKeylist)
        dummy = kms_client.describe_key(KeyId='alias/'+keyIdToSign,)

        # define the target bucket to delete
        s3_bucket = s3_resource.Bucket(bucketName)

        # list keys for all versions of objects
        list_keyids(s3_bucket)
    
        # list deletable keys for all versions of objects 
        list2del=list_keyids_todelete(s3_bucket)
    
        print("## the keys which you can delete")
        infoKeys(list2del)
    
        # disable keys and schedule keys deletion
        scheduleKeyDeletion(list2del)
        print("complete schedule to delete CMK")

        # delete all versions of objects and the bucket
        delete_bucket(s3_bucket)
        print("complete deleting the bucket : " + bucketName)

        # upload the file listing keys encrypting the objects in the bucket
        filename = uploadListAllKeys(filenameOfKeyList)
        print("the file listing keys encrypting the objects in the bucket : " + filename)
    
        # create hash from orginal data
        digest = sha256sum(filename)

        with open(tmpDir+digestFilePath, mode='w') as f:
            f.write(digest)
        ''' use the follow code if you need to test cli
        print("inputed digest : "+digest)
        print(" > "+digestFilePath)
        '''
    
        # sign to message with kms key
        signature=kmsSign(message=digest,KeyId=keyIdToSign)
        with open(tmpDir+signatureFilePath, mode='wb') as f:
            f.write(signature)
        ''' use the follow code if you need to test cli
        print(base64.b64encode(signature))
        print(" > "+signatureFilePath)
        '''
    
        # upload the file of key list and signature
        fileList=[filename,digestFilePath,signatureFilePath]
        uploadKeyList(fileList, bucketNameStoredKeylist)
        print("completed uploading files : "+filename+","+digestFilePath+","+signatureFilePath)

    except Exception as e:
        logger.error('fail on main function delStorageData()')
        logger.error(e)
        raise e

# list keys for all versions of objects
def list_keyids(s3_bucket):

    try:
        global listAllKeys
        global listPreKeyStatus

        # create the list for listing keys, and the list to delete key
        listAllKeys=[]
        listPreKeyStatus=[]

        # define a list of all versions of objects in "s3_bucket"
        versions = s3_bucket.object_versions.all()

        # Run for all object versions
        for version in versions:
        
            # get the metadata of the object_version            
            metadata=version.head()

            if 'SSEKMSKeyId' in metadata:
        
                # If "SSEKMSKeyId" is included in metadata of version
                # add keyid to "listAllKeys"
                keyid=metadata['SSEKMSKeyId']
                state=kms_client.describe_key(KeyId=keyid)['KeyMetadata']['KeyState']
                
                listAllKeys.append(keyid)
                listPreKeyStatus.append(state)
        return

    except Exception as e:
        logger.error('fail to list keys for all versions of objects')
        logger.error(e)
        raise e


# list deletable keys for all versions of objects 
def list_keyids_todelete(s3_bucket):

    try:
        global list2del
        global listPreKeyStatusToDel

        # create the list for listing keys, and the list to delete key
        list2del=[]
        listPreKeyStatusToDel=[]

        # define a list of all versions of objects in "s3_bucket"
        versions = s3_bucket.object_versions.all()

        # Run for all object versions
        for version in versions:
        
            # get the metadata of the object_version            
            metadata=version.head()

            if 'SSEKMSKeyId' in metadata:
        
                # If "SSEKMSKeyId" is included in metadata of version
                # add keyid to "listAllKeys"
                keyid=metadata['SSEKMSKeyId']

                # If the key corresponding to "keyid" is Customer Managed Key on KMS,
                # add it to the removal list "list2del"
                KeyMetadata=kms_client.describe_key(KeyId=keyid)['KeyMetadata']
                state=KeyMetadata['KeyState']

                if (state=="Enabled" or state=="Disabled"):
                    if (KeyMetadata['Origin']=="AWS_KMS" or KeyMetadata['Origin']=="AWS_CLOUDHSM"):
                        if KeyMetadata['KeyManager']=="CUSTOMER":
                            list2del.append(keyid)
                            listPreKeyStatusToDel.append(state)
                            ''' use the follow code if you need to test cli
                            print("keyid/status : "+keyid+"/"+state)
                            '''

        return list2del

    except Exception as e:
        logger.error('list deletable keys for all versions of objects')
        logger.error(e)
        raise e

# disable keys and schedule keys deletion
def scheduleKeyDeletion(keyids):
    
    try:
        # disable keys and schedule keys deletion
        for keyid in keyids:
            response = kms_client.disable_key(
                KeyId=keyid
            )
            response = kms_client.schedule_key_deletion(
                KeyId=keyid,
                PendingWindowInDays=7
            )
        return

    except Exception as e:
        logger.error('fail to disable keys and schedule keys deletion')
        logger.error(e)
        rollbackS3andKMS()
        raise e

# delete all versions of objects and the bucket
def delete_bucket(s3_bucket):
    try:
        
        # delete all versions of objects in "s3_bucket"
        versions = s3_bucket.object_versions.all()
        for version in versions:
            version.delete()

        # delete the bucket "s3_bucket"
        s3_bucket.delete()

        return
    except Exception as e:
        logger.error('fail to delete all versions of objects and the bucket')
        logger.error(e)
        rollbackS3andKMS()
        raise e

# upload the file listing keys encrypting the objects in the bucket
def uploadListAllKeys(filenameOfKeyList):
    try:
        global listAllKeys

        with open(tmpDir+filenameOfKeyList, mode='w') as f:
            writer = csv.writer(f)

            # write the header row
            elements=[
                "keyid",
                "Origin",
                "KeyManager",
                "KeyState",
                "<-PreviousKeyState"
            ]
            writer.writerow(elements)

            for i in range(len(listAllKeys)):

                # output to file as trailing that schedules erasable keys
                keyid=listAllKeys[i]
                KeyMetadata=kms_client.describe_key(KeyId=keyid)['KeyMetadata']

                elements=[
                    keyid,
                    KeyMetadata['Origin'],
                    KeyMetadata['KeyManager'],
                    KeyMetadata['KeyState'],
                    "<- "+listPreKeyStatus[i]
                ]
                writer.writerow(elements)

        return filenameOfKeyList

    except Exception as e:
        logger.error('fail to upload the file listing keys encrypting the objects in the bucket')
        logger.error(e)
        raise e 


# create hash from orginal data
def sha256sum(filePath):

    try:
        hash = hashlib.sha256()

        with open(tmpDir+filePath, 'rb') as f:
            while True:
                chunk = f.read(2048 * hash.block_size)
                if len(chunk) == 0:
                    break

                hash.update(chunk)

        digest = hash.hexdigest()

        return digest
    except Exception as e:
        logger.error('fail to create hash from orginal data')
        logger.error(e)
        raise e 

# sign to message with kms key
def kmsSign(message,KeyId):
    try:
        # sign to digest
        response = kms_client.sign(
            KeyId='alias/'+KeyId,
            Message=message,
            MessageType='RAW',
            SigningAlgorithm=SigningAlgorithm
        )
        return response['Signature']
    except Exception as e:
        logger.error('fail to sign to message with kms key')
        logger.error(e)
        raise e 

# upload the file of key list and signature
def uploadKeyList(fileList, bucketNameStoredKeylist):

    try:
        # store the file of key list and signature
        bucket = s3_resource.Bucket(bucketNameStoredKeylist)

        for targetFile in fileList:
            bucket.upload_file(tmpDir+targetFile, targetFile)
        return
    except Exception as e:
        logger.error('fail to upload the file of key list and signature')
        logger.error(e)
        raise e

# if it fails to delete objects or schedule keys, rollback about S3 and KMS
def rollbackS3andKMS():

    try:
        global list2del
        global listPreKeyStatusToDel

        # disable keys and schedule keys deletion
        for i in range(len(list2del)):
            keyid=list2del[i]
            state=listPreKeyStatusToDel[i]

            if state=='Enabled':
                kms_client.cancel_key_deletion(KeyId=keyid)
                kms_client.enable_key(KeyId=keyid)
            if state=='Disabled':
                kms_client.cancel_key_deletion(KeyId=keyid)
                kms_client.disable_key(KeyId=keyid)

        print("done: rollback about S3 and KMS")
        return

    except Exception as e:
        logger.error('fail to rollback about S3 and KMS')
        logger.error(e)
        raise e

# describe the key information on CLI as 'Origin' and 'KeyManager'
def infoKeys(keyids):

    try:
        for keyid in keyids:
            KeyMetadata=kms_client.describe_key(KeyId=keyid)['KeyMetadata']
            origin = KeyMetadata['Origin']
            KeyManager = KeyMetadata['KeyManager']

            ''' use the follow code if you need to test cli
            print("keyid : " + keyid)
            print("+ Origin : " + origin)
            print("+ KeyManager : " + KeyManager)
            '''

    except Exception as e:
        logger.error('fail to describe the key information on CLI as Origin and KeyManager')
        logger.error(e)
        raise e

# for test with using CLI
if __name__ == "__main__":

    # define arguments parse
    parser = argparse.ArgumentParser(description='delete backet')
    parser.add_argument('-b','--backetName', metavar='backetName',type=str, nargs='?',
                        help='target backet name')

    # set the paramters from the arguments
    args = parser.parse_args()

    # bucketName : the target bucket name to delete
    # filenameOfKeyList : define the filename for the file about key information
    # digestFilePath : the filename of digest for signature
    # signatureFilePath : the filename of signature
    # bucketNameStoredKeylist : the bucket name stored the file of key information and signature
    # KeyIdToSign : Key ID to sign at thekey list file

    # call the main function
    delStorageData(
        bucketName=args.backetName,
        filenameOfKeyList="keyListAboutDeletedS3Bucket.dat",
        digestFilePath="digest.txt",
        signatureFilePath="signature.binary",
        bucketNameStoredKeylist="****",
        keyIdToSign="****"
    )

