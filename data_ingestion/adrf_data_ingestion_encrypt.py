#!/usr/bin/python

import sys, getopt, os

import aws_encryption_sdk
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from Crypto.PublicKey import RSA

class LocalRSAMasterKeyProvider(RawMasterKeyProvider):
    provider_id = 'local-rsa-master-key'
    path_to_pem_file = ''

    def __init__(self, **kwargs):
        self._static_keys = {}

    def set_public_key_path(self, path):
        self.path_to_pem_file = path

    def _get_raw_key(self, key_id):
        if key_id not in self._static_keys.keys():
            static_key = open(self.path_to_pem_file, "rb").read()
            print("static_key=%s" % static_key)
            self._static_keys[key_id] = static_key
        else:
            static_key = self._static_keys[key_id]
        return WrappingKey(
            #RSA_OAEP_SHA1_MGF1
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
            wrapping_key=static_key,
            wrapping_key_type=EncryptionKeyType.PUBLIC,
        )

def encrypt_file(source_plaintext_filename, path_to_pem_file):
    """Encrypts a file.....

    :param str xxxxxxx: xxxxxxx
    :param str xxxxx: yyyyyyyy
    """
    print("Plaintext file in: %s [%s bytes]" % (source_plaintext_filename, len(source_plaintext_filename)))
    print("Public key file in: %s" % path_to_pem_file)

    ciphertext_filename = source_plaintext_filename + '.encrypted'

    # Load the key
    local_key_id = os.urandom(8)
    local_master_key_provider = LocalRSAMasterKeyProvider()
    local_master_key_provider.set_public_key_path(path_to_pem_file)
    local_master_key_provider.add_master_key(local_key_id)

    # Encrypt plaintext with local master keys
    with open(source_plaintext_filename, 'rb') as plaintext, open(ciphertext_filename, 'wb') as ciphertext:
        with aws_encryption_sdk.stream(
            source=plaintext,
            mode='e',
            key_provider=local_master_key_provider
        ) as encryptor:
            for chunk in encryptor:
                ciphertext.write(chunk)
    print("Encrypted file in: %s [%s bytes]" % (ciphertext_filename, len(ciphertext_filename)))

    return ciphertext_filename

def main(argv):
    file_to_encrypt = ''
    public_key_pem_file = ''
    # try:
    #     opts, args = getopt.getopt(argv,"hi:o:",["ifile=","pemfile="])
    # except getopt.GetoptError:
    #     print('adrf_data_ingestion_encrypt.py -i <inputfile> -p <public_key_pem_file>')
    #     sys.exit(2)
    # for opt, arg in opts:
    #     if opt == '-h':
    #         print('adrf_data_ingestion_encrypt.py -i <inputfile> -p <public_key_pem_file>')
    #         sys.exit()
    #     elif opt in ("-i", "--ifile"):
    #         file_to_encrypt = arg
    #     elif opt in ("-p", "--pemfile"):
    #         public_key_pem_file = arg
    # print 'File to encrypt: "', file_to_encrypt
    # print 'Publi key PEM file: "', public_key_pem_file

    print(len(argv))
    print(argv)
    file_to_encrypt = argv[0]
    public_key_pem_file = argv[1]

    encrypt_file(file_to_encrypt, public_key_pem_file)

if __name__ == "__main__":
   main(sys.argv[1:])
