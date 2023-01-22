package com.atatctech.arsa;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ARSATest {
    @Test
    public void main() throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException {
        ARSA.AKeyPair keyPair = ARSA.newKeys(2048);
        assert keyPair != null;
        System.out.println(ARSA.decrypt(ARSA.encrypt("test", keyPair.getPublicKey()), keyPair.getPrivateKey()));
    }
}
