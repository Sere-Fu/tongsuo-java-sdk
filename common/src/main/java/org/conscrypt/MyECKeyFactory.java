package org.conscrypt;

import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

public class MyECKeyFactory extends ECKeyFactoryGeneric<ECPublicKeySpec, ECPrivateKeySpec, OpenSSLECPublicKey, OpenSSLECPrivateKey> {
    public MyECKeyFactory() {
        super(
            ECPublicKeySpec.class,
            ECPrivateKeySpec.class,
            OpenSSLECPublicKey.class,
            OpenSSLECPrivateKey.class,
            NativeConstants.EVP_PKEY_EC);
    }
}
