# AWS KMS based XRPL Transaction Signing
[![npm version](https://badge.fury.io/js/xrpl-kms.svg)](https://badge.fury.io/js/xrpl-kms)

This package provides the tools to be able to sign and receive XRPL transactions using private keys stored in AWS KMS hardware modules.

## Installation

to install the npm module on your typescript or node project run:

`npm install xrpl-kms --save`

## Preparation
1. Create ECDSA secp256k1 key in AWS KMS, and get the KeyId.
2. Create AWS IAM user with programmatic access to AWS KMS.
3. Get the AccessKey, SecretKey pair for the IAM user.

After that is done, we can start using the package. We will first need to get the xrpl address generated from the KMS public key, and fund the account with at least 10xrp to activate it. Then we can start signing transactions. There is example code for both funding an account and signing transactions in the example.ts file. You can fill in the aws parameters and run it with ts-node to try it yourself!

## Example: Funding the KMS account

```typescript
import { Client, Wallet, xrpToDrops } from "xrpl";
import { XrplKmsService } from "xrpl-kms";

// Fill in with your AWS credentials
const awsAccessKey = "";
const awsSecretKey = "";
const awsRegion = "us-east-1";
const kmsKeyId = "";

// Funds the AWS account with 10XRP from a testnet account funded from the faucet
async function txFund() {
    const xrplKmsService = new XrplKmsService(awsAccessKey, awsSecretKey, awsRegion, kmsKeyId);

    const client = new Client("wss://s.altnet.rippletest.net:51233");
    await client.connect();
    // 1. Get Address
    let xrpAddr = await xrplKmsService.getXrpAddress();
    // 2. Generate Transaction
    const transaction = await client.autofill({
        TransactionType: "Payment",
        Account: "r9QsP3KmmwGLmak1L2ZWfVosf8K6Xm5ea8",
        Amount: xrpToDrops(10),
        Destination: xrpAddr,
    });
    // 3. Sign Transaction
    // Change the account if it ran out of funds
    const wallet = Wallet.fromSecret("shM4SKz4em6MMLnpcRXYndt9QTiz6");
    const signed = wallet.sign(transaction);
    console.log("Payload: ", signed.tx_blob);
    // 4. Broadcast Transaction
    const tx = await client.submitAndWait(signed.tx_blob);
    console.log("Transaction: ", tx);
    await client.disconnect();
}
```

## Example: Signing and broadcasting a transaction from a KMS account

```typescript
import { Client, verifySignature } from "xrpl";
import { XrplKmsService } from "xrpl-kms";

// Fill in with your AWS credentials
const awsAccessKey = "";
const awsSecretKey = "";
const awsRegion = "us-east-1";
const kmsKeyId = "";

async function txTest() {
    const xrplKmsService = new XrplKmsService(awsAccessKey, awsSecretKey, awsRegion, kmsKeyId);

    const client = new Client("wss://s.altnet.rippletest.net:51233");
    await client.connect();

    // 1. Get Address
    let xrpAddr = await xrplKmsService.getXrpAddress();
    // 2. Generate Transaction
    const transaction = await client.autofill({
        TransactionType: "Payment",
        Account: xrpAddr,
        Amount: "200",
        Destination: "rUCzEr6jrEyMpjhs4wSdQdz4g8Y382NxfM",
    });
    // 3. Sign Transaction
    const signed = await xrplKmsService.signXrpTransaction(transaction);
    // 4. Verify Signature
    const verified = verifySignature(signed.payload);
    console.log("verified: ", verified);
    // 5. Broadcast Transaction
    const tx = await client.submitAndWait(signed.payload);
    console.log("Transaction: ", tx);

    await client.disconnect();
}
```

