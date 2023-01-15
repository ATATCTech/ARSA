package com.atatctech.arsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ARSA {
    public static class AKeyPair {
        protected final APublicKey publicKey;
        protected final APrivateKey privateKey;
        protected final int keyLength;

        public AKeyPair(APublicKey publicKey, APrivateKey privateKey, int keyLength) throws InvalidKeySpecException, NoSuchAlgorithmException {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.keyLength = keyLength;
        }

        public APublicKey getPublicKey() {
            return publicKey;
        }

        public APrivateKey getPrivateKey() {
            return privateKey;
        }

        public int getKeyLength() {
            return keyLength;
        }
    }

    public static class APublicKey {
        protected final String publicKey;
        protected final int keyLength;
        protected final PublicKey n;

        protected APublicKey(String publicKeyString, PublicKey publicKeyObject, int keyLength) {
            this.publicKey = publicKeyString;
            this.keyLength = keyLength;
            n = publicKeyObject;
        }

        public int getKeyLength() {
            return keyLength;
        }

        public PublicKey getPublicKey() {
            return n;
        }

        public static APublicKey importPublicKey(String publicKey, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
            return new APublicKey(publicKey, keyFactory.generatePublic(keySpec), keyLength);
        }

        public static APublicKey importPublicKey(PublicKey publicKey, int keyLength) {
            return new APublicKey(Base64.getEncoder().encodeToString(publicKey.getEncoded()), publicKey, keyLength);
        }

        @Override
        public String toString() {
            return publicKey;
        }
    }

    public static class APrivateKey {
        protected final String privateKey;
        protected final int keyLength;
        protected final PrivateKey n;

        protected APrivateKey(String privateKeyString, PrivateKey privateKeyObject, int keyLength) {
            this.privateKey = privateKeyString;
            this.keyLength = keyLength;
            n = privateKeyObject;
        }

        public int getKeyLength() {
            return keyLength;
        }

        public PrivateKey getPrivateKey() {
            return n;
        }

        public static APrivateKey importPrivateKey(String privateKey, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
            return new APrivateKey(privateKey, keyFactory.generatePrivate(keySpec), keyLength);
        }

        public static APrivateKey importPrivateKey(PrivateKey privateKey, int keyLength) {
            return new APrivateKey(Base64.getEncoder().encodeToString(privateKey.getEncoded()), privateKey, keyLength);
        }

        @Override
        public String toString() {
            return privateKey;
        }
    }

    public static AKeyPair newKeys(int keyLength) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            return new AKeyPair(APublicKey.importPublicKey(keyPair.getPublic(), keyLength), APrivateKey.importPrivateKey(keyPair.getPrivate(), keyLength), keyLength);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {
            return null;
        }
    }

    public static String sign(String content, APrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey.getPrivateKey());
        signer.update(content.getBytes());
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    public static boolean verify(String content, String signature, APublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initVerify(publicKey.getPublicKey());
        signer.update(content.getBytes());
        return signer.verify(Base64.getDecoder().decode(signature));
    }

    public static String encrypt(String content, APublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey.getPublicKey());
        return process(content.getBytes(), publicKey.getKeyLength() / 8 - 11, cipher);
    }

    public static String decrypt(String content, APrivateKey privateKey) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey.getPrivateKey());
        return process(Base64.getDecoder().decode(content), privateKey.getKeyLength() / 8, cipher);
    }

    static String process(byte[] contentBytes, int paraLength, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException, IOException {
        int contentLength = contentBytes.length;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        while (contentLength - offset > 0) {
            if (contentLength - offset > paraLength) {
                cache = cipher.doFinal(contentBytes, offset, paraLength);
            } else {
                cache = cipher.doFinal(contentBytes, offset, contentLength - offset);
            }
            byteArrayOutputStream.write(cache, 0, cache.length);
            offset += paraLength;
        }
        try {
            return byteArrayOutputStream.toString();
        } finally {
            byteArrayOutputStream.close();
        }
    }
}
