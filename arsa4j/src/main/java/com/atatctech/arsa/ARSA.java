package com.atatctech.arsa;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

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

public final class ARSA {
    public static class AKeyPair {
        protected final APublicKey publicKey;
        protected final APrivateKey privateKey;
        protected final int keyLength;

        public AKeyPair(@NotNull APublicKey publicKey, @NotNull APrivateKey privateKey, int keyLength) throws InvalidKeySpecException, NoSuchAlgorithmException {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.keyLength = keyLength;
        }

        public @NotNull APublicKey getPublicKey() {
            return publicKey;
        }

        public @NotNull APrivateKey getPrivateKey() {
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

        protected APublicKey(@NotNull String publicKeyString, @NotNull PublicKey publicKeyObject, int keyLength) {
            this.publicKey = publicKeyString;
            this.keyLength = keyLength;
            n = publicKeyObject;
        }

        public int getKeyLength() {
            return keyLength;
        }

        public @NotNull PublicKey getPublicKey() {
            return n;
        }

        public static @NotNull APublicKey importPublicKey(@NotNull String publicKey, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
            return new APublicKey(publicKey, keyFactory.generatePublic(keySpec), keyLength);
        }

        public static @NotNull APublicKey importPublicKey(@NotNull PublicKey publicKey, int keyLength) {
            return new APublicKey(Base64.getEncoder().encodeToString(publicKey.getEncoded()), publicKey, keyLength);
        }

        @Override
        public @NotNull String toString() {
            return publicKey;
        }
    }

    public static class APrivateKey {
        protected final String privateKey;
        protected final int keyLength;
        protected final PrivateKey n;

        protected APrivateKey(@NotNull String privateKeyString, @NotNull PrivateKey privateKeyObject, int keyLength) {
            this.privateKey = privateKeyString;
            this.keyLength = keyLength;
            n = privateKeyObject;
        }

        public int getKeyLength() {
            return keyLength;
        }

        public @NotNull PrivateKey getPrivateKey() {
            return n;
        }

        public static @NotNull APrivateKey importPrivateKey(@NotNull String privateKey, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
            return new APrivateKey(privateKey, keyFactory.generatePrivate(keySpec), keyLength);
        }

        public static @NotNull APrivateKey importPrivateKey(@NotNull PrivateKey privateKey, int keyLength) {
            return new APrivateKey(Base64.getEncoder().encodeToString(privateKey.getEncoded()), privateKey, keyLength);
        }

        @Override
        public @NotNull String toString() {
            return privateKey;
        }
    }

    public static @Nullable AKeyPair newKeys(int keyLength) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            return new AKeyPair(APublicKey.importPublicKey(keyPair.getPublic(), keyLength), APrivateKey.importPrivateKey(keyPair.getPrivate(), keyLength), keyLength);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {
            return null;
        }
    }

    public static @NotNull String sign(@NotNull String content, @NotNull APrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey.getPrivateKey());
        signer.update(content.getBytes());
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    public static boolean verify(@NotNull String content, @NotNull String signature, @NotNull APublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initVerify(publicKey.getPublicKey());
        signer.update(content.getBytes());
        return signer.verify(Base64.getDecoder().decode(signature));
    }

    public static @NotNull String encrypt(@NotNull String content, @NotNull APublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey.getPublicKey());
        return Base64.getEncoder().encodeToString(process(content.getBytes(), publicKey.getKeyLength() / 8 - 11, cipher));
    }

    public static @NotNull String decrypt(@NotNull String content, @NotNull APrivateKey privateKey) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey.getPrivateKey());
        return new String(process(Base64.getDecoder().decode(content), privateKey.getKeyLength() / 8, cipher));
    }

    static byte[] process(byte[] contentBytes, int paraLength, @NotNull Cipher cipher) throws IllegalBlockSizeException, BadPaddingException, IOException {
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
            return byteArrayOutputStream.toByteArray();
        } finally {
            byteArrayOutputStream.close();
        }
    }
}
