# ADRF Encryption SDK

This is the ADRF Encryption SDK used to ensure data encryption in rest and in transit.

## Installation

ADRF Encryption SDK uses the AWS Encryption SDK which uses ensures the best practices of encryption algorithms, message format and all desired features by ADRF.

The first step is to install ADRF Encryption SDK using pip: `pip install -r requirements.txt`

## Simple Usage

To simple encrypt data using this SDK, you can use the python scripts in the `/default_encryption.py`

This will require you to use the AWS SDK connection and is not possible to use this without internet connectivity (like in a Red Room, for example).

### Ingestion

To encrypt data to send it to ADRF you should use the scripts in the `data_ingestion` folder.
