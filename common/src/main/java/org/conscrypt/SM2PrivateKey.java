package org.conscrypt;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

public class SM2PrivateKey extends OpenSSLECPrivateKey{
    private static final long serialVersionUID = 3215842926808298020L;

    private static final String ALGORITHM = "SM2";

    SM2PrivateKey(OpenSSLKey key) {
        super(OpenSSLECGroupContext.getCurveByName(ALGORITHM), key);  // faster than super(key)
    }

    SM2PrivateKey(OpenSSLECGroupContext group, OpenSSLKey key) throws IllegalArgumentException{
        super(group, key);
        if (!ALGORITHM.equals(group.getCurveName())) {
            throw new IllegalArgumentException("SM2 curve in needed");
        }
    }

    SM2PrivateKey(ECPrivateKeySpec ecKeySpec) throws InvalidKeySpecException {
        super(ecKeySpec);
        if (!(ecKeySpec instanceof SM2PrivateKeySpec)) {
            throw new InvalidKeySpecException("Must be SM2PrivateKeySpec");
        }
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public ECParameterSpec getParams() {
        return SM2ParameterSpec.instance();
    }
}
