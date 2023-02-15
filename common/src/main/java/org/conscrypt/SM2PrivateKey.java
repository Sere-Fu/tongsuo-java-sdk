package org.conscrypt;

import java.security.spec.InvalidKeySpecException;

public class SM2PrivateKey extends OpenSSLECPrivateKey{
    private static final long serialVersionUID = 3215842926808298020L;

    private static final String ALGORITHM = "SM2";

    SM2PrivateKey(OpenSSLKey key) {
        super(OpenSSLECGroupContext.getCurveByName(ALGORITHM), key);  // faster than super(key)
    }

    SM2PrivateKey(SM2PrivateKeySpec sm2KeySpec) throws InvalidKeySpecException {
        super(sm2KeySpec);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }
}
