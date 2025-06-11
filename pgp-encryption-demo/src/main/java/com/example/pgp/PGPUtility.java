package com.example.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PGPUtility {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String jsonData = "{\"accountNumber\": \"2150622522\", \"institutionCode\": \"1234\"}";
            String publicKeyPath = "C:\\Users\\LAJIDE\\Downloads\\PGP-Test\\PGP-Test\\public.asc";
        String privateKeyPath = "C:\\Users\\LAJIDE\\Downloads\\PGP-Test\\PGP-Test\\private.asc";
        String passphrase = "phrase";

        String encrypted = encrypt(jsonData, publicKeyPath);
        System.out.println("Encrypted:\n" + encrypted);

        String decrypted = decrypt(encrypted, privateKeyPath, passphrase);
        System.out.println("Decrypted:\n" + decrypted);
    }

    public static String encrypt(String data, String publicKeyPath) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PGPPublicKey encKey = readPublicKey(new FileInputStream(publicKeyPath));
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);

        try (OutputStream armoredOut = new ArmoredOutputStream(out)) {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC")
            );

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

            try (OutputStream cOut = encGen.open(armoredOut, new byte[4096])) {
                cOut.write(bytes);
            }
        }

        return out.toString(StandardCharsets.UTF_8);
    }

    public static String decrypt(String encryptedText, String privateKeyPath, String passphrase) throws Exception {
        InputStream in = new ByteArrayInputStream(encryptedText.getBytes(StandardCharsets.UTF_8));
        InputStream keyIn = new FileInputStream(privateKeyPath);

        in = PGPUtil.getDecoderStream(in);
        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        for (PGPEncryptedData data : enc) {
            PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) data;
            PGPSecretKey secretKey = pgpSec.getSecretKey(pked.getKeyID());

            if (secretKey != null) {
                PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray());
                privateKey = secretKey.extractPrivateKey(decryptor);
                pbe = pked;
                break;
            }
        }

        if (privateKey == null || pbe == null) {
            throw new IllegalArgumentException("Private key for decryption not found.");
        }

        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            plainFact = new JcaPGPObjectFactory(cData.getDataStream());
            message = plainFact.nextObject();
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (message instanceof PGPLiteralData) {
            InputStream unc = ((PGPLiteralData) message).getInputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
        } else {
            throw new PGPException("Unsupported PGP message type.");
        }

        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static PGPPublicKey readPublicKey(InputStream in) throws Exception {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());

        for (PGPPublicKeyRing keyRing : pgpPub) {
            for (PGPPublicKey key : keyRing) {
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("No encryption key found in the public key ring.");
    }
}
