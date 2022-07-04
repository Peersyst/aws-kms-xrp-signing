import { KMS } from 'aws-sdk';
import * as asn1 from 'asn1.js';
import BN from 'bn.js';
import * as hashjs from 'hash.js';
import { encodeForSigning, encode } from 'ripple-binary-codec';
import { Client, Transaction, Wallet, xrpToDrops, verifySignature } from 'xrpl';
import { hashSignedTx } from 'xrpl/dist/npm/utils/hashes';
import { deriveAddress } from "ripple-keypairs";
const Signature = require("elliptic/lib/elliptic/ec/signature");

const kms = new KMS({
    accessKeyId: '', // credentials for your IAM user with KMS access
    secretAccessKey: '', // credentials for your IAM user with KMS access
    region: 'us-east-1',
    apiVersion: '2014-11-01',
});

const keyId = '';

const EcdsaSigAsnParse = asn1.define('EcdsaSig', function(this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3 
    this.seq().obj( 
        this.key('r').int(), 
        this.key('s').int(),
    );
});

const EcdsaPubKey = asn1.define('EcdsaPubKey', function(this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj( 
        this.key('algo').seq().obj(
            this.key('a').objid(),
            this.key('b').objid(),
        ),
        this.key('pubKey').bitstr()
    );
});

async function sign(msg: any, keyId: string) {
    const params : KMS.SignRequest = {
        // key id or 'Alias/<alias>'
        KeyId: keyId, 
        Message: msg, 
        // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
        SigningAlgorithm: 'ECDSA_SHA_256',
        MessageType: 'DIGEST' 
    };
    const res = await kms.sign(params).promise();
    return res;
}

async function getPublicKey(keyPairId: string): Promise<Buffer> {
    const pubKey = await kms.getPublicKey({
        KeyId: keyPairId
    }).promise();
    const publicKeyBuffer = pubKey.PublicKey as Buffer;

    console.log("Encoded Pub Key: " + publicKeyBuffer.toString('hex'));

    // The public key is ASN1 encoded in a format according to 
    // https://tools.ietf.org/html/rfc5480#section-2
    // I used https://lapo.it/asn1js to figure out how to parse this 
    // and defined the schema in the EcdsaPubKey object
    const res = EcdsaPubKey.decode(publicKeyBuffer, 'der');
    const uncompressed : Buffer = res.pubKey.data;

    console.log("Uncompressed Pub Key: ", uncompressed.toString("hex"));

    const compressedPubKey = compressPubKey(uncompressed);

    console.log("Compressed Pub Key: ", compressedPubKey.toString("hex"));

    return compressedPubKey;
}

// Finds the compressed form of the public key (Only R is needed for EC keys, 02 / 03 prefix depending on S even or odd)
function compressPubKey(publicKey: Buffer): Buffer {
    const header =
        parseInt(publicKey.toString("hex").slice(publicKey.length*2 - 2, publicKey.length*2), 16) % 2
            ? "03"
            : "02";
    return Buffer.from(header + publicKey.toString("hex").slice(2, 66), "hex");
}

function getXrpAddress(publicKey: Buffer): string {
    const address = deriveAddress(publicKey.toString("hex"));
    console.log("Address: ", address);
    return address;
}

async function findXrpSig(transaction: Transaction, pubKey: string) {
    const txToSignAndEncode = {...transaction};
    txToSignAndEncode.SigningPubKey = pubKey;

    const encodedForSigning = encodeForSigning(txToSignAndEncode);
    const encodedHash = hashjs.sha512().update(Buffer.from(encodedForSigning, "hex")).digest().slice(0, 32);
    const awsSignature = await sign(Buffer.from(encodedHash), keyId);
    if (awsSignature.Signature == undefined) {
        throw new Error('Signature is undefined.');
    }

    const decoded = EcdsaSigAsnParse.decode(awsSignature.Signature, 'der');
    const r : BN = decoded.r;
    let s : BN = decoded.s;

    // Make it canonical (To avoid replay attack with inverse signature, only one is allowed)
    const secp256k1N = new BN("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16); // max value on the curve
    const secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
    if (s.gt(secp256k1halfN)) {
        s = secp256k1N.sub(s);
    }

    const signatureBytes = (new Signature({ r: r.toString(16), s: s.toString(16) })).toDER();
    const signature = Array.from(signatureBytes, (byteValue: any) => {
        const hex = byteValue.toString(16).toUpperCase()
        return hex.length > 1 ? hex : `0${hex}`
      }).join('')

    txToSignAndEncode.TxnSignature = signature;

    const serialized = encode(txToSignAndEncode);

    return {
        tx_blob: serialized,
        hash: hashSignedTx(serialized),
      }
}

// Funds the AWS account with 10XRP from a faucet account
async function txFund() {
    const client = new Client("wss://s.altnet.rippletest.net:51233");
    await client.connect();
    // 1. Get Address
    let pubKey = await getPublicKey(keyId);
    let xrpAddr = getXrpAddress(pubKey);
    // 2. Generate Transaction
    const transaction = await client.autofill({
        TransactionType: "Payment",
        Account: "r9QsP3KmmwGLmak1L2ZWfVosf8K6Xm5ea8",
        Amount: xrpToDrops(10),
        Destination: xrpAddr,
    });
    // 3. Sign Transaction
    const wallet = Wallet.fromSecret("shM4SKz4em6MMLnpcRXYndt9QTiz6");
    const signed = wallet.sign(transaction);
    console.log("Blob: ", signed.tx_blob);
    // 4. Broadcast Transaction
    const tx = await client.submitAndWait(signed.tx_blob);
    console.log("Transaction: ", tx);
    await client.disconnect();
}

async function txTest() {
    const client = new Client("wss://s.altnet.rippletest.net:51233");
    await client.connect();

    // 1. Get Address
    let pubKey = await getPublicKey(keyId);
    let xrpAddr = getXrpAddress(pubKey);
    // 2. Generate Transaction
    const transaction = await client.autofill({
        TransactionType: "Payment",
        Account: xrpAddr,
        Amount: "200",
        Destination: "rUCzEr6jrEyMpjhs4wSdQdz4g8Y382NxfM",
    });
    // 3. Sign Transaction
    const signed = await findXrpSig(transaction, pubKey.toString("hex"));
    // 4. Verify Signature
    const verified = verifySignature(signed.tx_blob);
    console.log("verified: ", verified);
    // 5. Broadcast Transaction
    const tx = await client.submitAndWait(signed.tx_blob);
    console.log("Transaction: ", tx);

    await client.disconnect();
}

txTest();
