package com.example.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;

public class PGPUtility {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String passphrase = "phrase";
        String jsonData = new String(Files.readAllBytes(Paths.get("C:\\Users\\LAJIDE\\Downloads\\PGP-Test\\PGP-Test\\data.json")), StandardCharsets.UTF_8);

        String publicKeyPath = "C:\\Users\\LAJIDE\\Downloads\\PGP-Test\\PGP-Test\\uudara_remita_public.asc";
        String privateKeyPath = "C:\\Users\\LAJIDE\\Downloads\\PGP-Test\\PGP-Test\\uudara_remita_private.asc";

        String formatedpayload = validatePayload (jsonData);

        String decrypted = null;
        if (formatedpayload.startsWith("{") && formatedpayload.endsWith("}")) {
            String encrypted = encrypt(formatedpayload, publicKeyPath);
            System.out.println("Encrypted:\n" + cleanEncryptedOutput(encrypted));

            decrypted = decrypt(encrypted, privateKeyPath, passphrase);
            System.out.println("Decrypted:\n" + decrypted.replaceAll("\\s+", ""));
        } else {
            System.out.println("Encrypted formatedpayload Data:\n" + cleanEncryptedOutput(formatedpayload));

            decrypted = decrypt(formatedpayload, privateKeyPath, passphrase);
            System.out.println("Already Decrypted:\n" + decrypted.replaceAll("\\s+", ""));
        }
    }

    public  static String validatePayload(String json) {
        if (json == null || json.trim().isEmpty()) return null;

        String payload = json.trim();

        // Remove outer braces
        if (payload.startsWith("{") && json.endsWith("}")) {
            payload = json.substring(1, json.length() - 1).trim();
        }

        // Split key-value pairs
        String[] pairs = payload.split(",");

        for (String pair : pairs) {
            String[] keyValue = pair.split(":", 2);
            if (keyValue.length == 2) {
                String key = keyValue[0].trim().replaceAll("^\"|\"$", "");
                String value = keyValue[1].trim().replaceAll("^\"|\"$", "");

                if ("response".equals(key)) {
                    return value;
                }
            }
        }

        return json;
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
                PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
                try (OutputStream pOut = literalGen.open(cOut, PGPLiteralData.BINARY, "data", bytes.length, new java.util.Date())) {
                    pOut.write(bytes);
                }
            }
        }

        return out.toString(StandardCharsets.UTF_8);
    }

    public static String decrypt(String encryptedText, String privateKeyPath, String passphrase) throws Exception {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedText.getBytes(StandardCharsets.UTF_8)));
        InputStream keyIn = new FileInputStream(privateKeyPath);

        PGPObjectFactory pgpFactory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        Object o = pgpFactory.nextObject();
        PGPEncryptedDataList encList;

        if (o instanceof PGPEncryptedDataList) {
            encList = (PGPEncryptedDataList) o;
        } else {
            encList = (PGPEncryptedDataList) pgpFactory.nextObject();
        }

        PGPSecretKeyRingCollection secretKeyRingCollection =
                new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData encryptedData = null;

        for (PGPEncryptedData ed : encList) {
            PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) ed;
            PGPSecretKey secretKey = secretKeyRingCollection.getSecretKey(pked.getKeyID());
            if (secretKey != null) {
                PBESecretKeyDecryptor decryptor =
                        new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray());
                privateKey = secretKey.extractPrivateKey(decryptor);
                encryptedData = pked;
                break;
            }
        }

        if (privateKey == null || encryptedData == null) {
            throw new IllegalArgumentException("Matching private key not found.");
        }

        InputStream clear = encryptedData.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
        PGPObjectFactory plainFactory = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        Object message = plainFactory.nextObject();

        if (message instanceof PGPCompressedData) {
            message = new PGPObjectFactory(((PGPCompressedData) message).getDataStream(), new JcaKeyFingerprintCalculator()).nextObject();
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (message instanceof PGPLiteralData) {
            InputStream dataIn = ((PGPLiteralData) message).getInputStream();
            int ch;
            while ((ch = dataIn.read()) >= 0) {
                out.write(ch);
            }
        } else {
            throw new PGPException("Invalid PGP message format.");
        }

        return out.toString(StandardCharsets.UTF_8);
    }

    private static PGPPublicKey readPublicKey(InputStream in) throws Exception {
        PGPPublicKeyRingCollection keyRings =
                new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
        for (PGPPublicKeyRing keyRing : keyRings) {
            for (PGPPublicKey key : keyRing) {
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("No encryption key found in public key ring.");
    }

    private static String cleanEncryptedOutput(String rawEncryptedText) {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new StringReader(rawEncryptedText));
        String line;
        try {
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                // Remove all PGP headers/footers and version lines
                if (!line.equals("-----BEGIN PGP MESSAGE-----") &&
                    !line.equals("-----END PGP MESSAGE-----") &&
                    !line.startsWith("Version:") &&
                    !line.isEmpty()) {
                    sb.append(line);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // Remove all whitespace from the result
        return sb.toString().replaceAll("\\s+", "");
    }
}

