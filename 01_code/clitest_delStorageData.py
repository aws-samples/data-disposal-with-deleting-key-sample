#!/usr/bin/env python3
import json
import argparse
import delStorageData

# for test with using CLI
if __name__ == "__main__":

    # define arguments parse
    parser = argparse.ArgumentParser(description='delete backet')
    parser.add_argument('-b','--backetName', metavar='backetName', default="dsd-backet-20200529r09",type=str, nargs='?',
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
    delStorageData.delStorageData(
        bucketName=args.backetName,
        filenameOfKeyList="keyListAboutDeletedS3Bucket.dat",
        digestFilePath="digest.txt",
        signatureFilePath="signature.binary",
        bucketNameStoredKeylist="dsd-bucket-for-list-sotred",
        keyIdToSign="dsd-key-for-signature-ecc_secg_p256k1_r02"
    )
    print("the CLI to verify:")
    print("$ aws kms verify  --key-id alias/dsd-key-for-signature-ecc_secg_p256k1_r02 --message-type RAW --signing-algorithm ECDSA_SHA_256  --message fileb:///tmp/digest.txt --signature fileb:///tmp/signature.binary")


