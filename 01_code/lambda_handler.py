import json
import boto3
import logging
import re
import delStorageData

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# main functions
def lambda_handler(event, context):

    try:
        # check validation
        for key in event.keys():
            print("check:", event[key])
            if not checkValidation(event[key]):
                raise("validation error")

        # BucketName : the target bucket name to delete
        bucketName=event['bucketName']

        # bucketNameStoredKeylist : the bucket name stored the file of key information and signature
        bucketNameStoredKeylist=event['bucketNameStoredKeylist']

        # KeyIdToSign : Key ID to sign at thekey list file
        keyIdToSign=event['keyIdToSign']

        # filenameOfKeyList : define the filename for the file about key information
        if('filenameOfKeyList' in event):
            filenameOfKeyList=event['filenameOfKeyList']
        else:
            filenameOfKeyList="keyListAboutDeletedS3Bucket.dat"

        # digestFilePath : the filename of digest for signature
        if('digestFilePath' in event):
            digestFilePath=event['digestFilePath']
        else:
            digestFilePath="digest.txt"

        # signatureFilePath : the filename of signature
        if('signatureFilePath' in event):
            signatureFilePath=event['signatureFilePath']
        else:
            signatureFilePath="signature.binary"

        ''' use the follow code if you need to test cli
        print("bucketName : "+bucketName)
        print("filenameOfKeyList : "+filenameOfKeyList)
        print("digestFilePath : "+digestFilePath)
        print("signatureFilePath : "+signatureFilePath)
        print("bucketNameStoredKeylist : "+bucketNameStoredKeylist)
        print("keyIdToSign : "+keyIdToSign)
        '''

        # call main function
        delStorageData.delStorageData(
            bucketName=bucketName,
            filenameOfKeyList=filenameOfKeyList,
            digestFilePath=digestFilePath,
            signatureFilePath=signatureFilePath,
            bucketNameStoredKeylist=bucketNameStoredKeylist,
            keyIdToSign=keyIdToSign
        )
    except Exception as e:
        logger.error('fail on lambda_handler function')
        logger.error(e)
        raise e

# check validation
def checkValidation(word):

    try:
        return bool(re.match('^[\w\.\-\_]{1,50}$', word))

    except Exception as e:
        logger.error('fail to check validation')
        logger.error(e)
        raise e
