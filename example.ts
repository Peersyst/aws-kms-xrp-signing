import { Client, Transaction, Wallet, xrpToDrops, verifySignature } from "xrpl";
import { XrplKmsService } from "./src/XrplKmsService";

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
    const wallet = Wallet.fromSecret("shM4SKz4em6MMLnpcRXYndt9QTiz6"); // Change the account if it ran out of funds
    const signed = wallet.sign(transaction);
    console.log("Blob: ", signed.tx_blob);
    // 4. Broadcast Transaction
    const tx = await client.submitAndWait(signed.tx_blob);
    console.log("Transaction: ", tx);
    await client.disconnect();
}

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

txTest();