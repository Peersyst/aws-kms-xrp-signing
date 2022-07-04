# AWS KMS based Ripple Tx Signing
This repo shows how to sign a Ripple transaction using AWS KMS. 

## Prep
1. Create ECDSA secp256k1 key in AWS KMS
2. Create AWS IAM user with programmatic access to AWS KMS.
3. Run the script to generate the XRP address and fund the account with min 10XRP to activate it.
