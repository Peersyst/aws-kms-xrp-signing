import { KMS } from 'aws-sdk';
import * as asn1 from 'asn1.js';
import BN from 'bn.js';
import * as hashjs from 'hash.js';
import { encodeForSigning, encode } from 'ripple-binary-codec';
import { Transaction } from 'xrpl';
import { hashSignedTx } from 'xrpl/dist/npm/utils/hashes';
import { deriveAddress } from "ripple-keypairs";
const Signature = require("elliptic/lib/elliptic/ec/signature");

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

export interface SignedTransaction {
    payload: string;
    hash: string;
}

export class XrplKmsService {
    private readonly kms: KMS;
    private readonly kmsKeyId: string;

    constructor(
        awsAccessKey: string,
        awsSecretKey: string,
        awsRegion: string,
        kmsKeyId: string,
    ) {
        this.kmsKeyId = kmsKeyId;
        this.kms = new KMS({
            accessKeyId: awsAccessKey,
            secretAccessKey: awsSecretKey,
            region: awsRegion,
            apiVersion: "2014-11-01",
        });
    }

    private async sign(msg: Buffer): Promise<{ r: BN; s: BN }> {
        const params: KMS.SignRequest = {
            KeyId: this.kmsKeyId,
            Message: msg,
            SigningAlgorithm: "ECDSA_SHA_256",
            MessageType: "DIGEST",
        };
        const res = await this.kms.sign(params).promise();
        if (res.Signature == undefined) {
            throw new Error("Signature is undefined.");
        }

        const decoded = EcdsaSigAsnParse.decode(res.Signature, "der");
        const r: BN = decoded.r;
        let s: BN = decoded.s;

        // To avoid replay attack with inverse signature, only one half of the curve is allowed as a valid signature
        const secp256k1N = new BN("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
        const secp256k1halfN = secp256k1N.div(new BN(2));
        if (s.gt(secp256k1halfN)) {
            s = secp256k1N.sub(s);
        }
        return { r, s };
    }

    private async getUncompressedPublicKey(): Promise<Buffer> {
        const pubKey = await this.kms
            .getPublicKey({
                KeyId: this.kmsKeyId,
            })
            .promise();
        const publicKeyBuffer = pubKey.PublicKey as Buffer;

        const res = EcdsaPubKey.decode(publicKeyBuffer, "der");
        return res.pubKey.data;
    }

    // Finds the compressed form of the public key (Only R is needed for EC keys, 02 / 03 prefix depending on S even or odd)
    private async getCompressedPublicKey(): Promise<Buffer> {
        const uncompressed = await this.getUncompressedPublicKey();
        const header =
            parseInt(uncompressed.toString("hex").slice(uncompressed.length * 2 - 2, uncompressed.length * 2), 16) % 2 ? "03" : "02";
        return Buffer.from(header + uncompressed.toString("hex").slice(2,66), "hex");
    }

    async getXrpAddress(): Promise<string> {
        const publicKey = await this.getCompressedPublicKey();
        return deriveAddress(publicKey.toString("hex"));
    }

    async signXrpTransaction(transaction: Transaction): Promise<SignedTransaction> {
        const publicKey = await this.getCompressedPublicKey();
        const txToSignAndEncode = {...transaction};
        txToSignAndEncode.SigningPubKey = publicKey.toString("hex");

        const encodedForSigning = encodeForSigning(txToSignAndEncode);
        const encodedHash = hashjs.sha512().update(Buffer.from(encodedForSigning, "hex")).digest().slice(0, 32);
        const { r, s } = await this.sign(Buffer.from(encodedHash));

        const signatureBytes = (new Signature({ r: r.toString(16), s: s.toString(16) })).toDER();
        const signature = Buffer.from(signatureBytes).toString("hex");
        txToSignAndEncode.TxnSignature = signature;

        const serialized = encode(txToSignAndEncode);
        return {
            payload: serialized,
            hash: hashSignedTx(serialized),
        }
    }
}