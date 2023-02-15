package org.conscrypt;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

public class SM2PublicKey extends OpenSSLECPublicKey{
    private static final long serialVersionUID = 3215842926808298020L;

    private static final String ALGORITHM = "SM2";

    SM2PublicKey(OpenSSLKey key) {
        super(OpenSSLECGroupContext.getCurveByName(ALGORITHM), key);  // faster than super(key)
    }

    SM2PublicKey(OpenSSLECGroupContext group, OpenSSLKey key) throws IllegalArgumentException{
        super(group, key);
        if (!ALGORITHM.equals(group.getCurveName())) {
            throw new IllegalArgumentException("SM2 curve in needed");
        }
    }

    SM2PublicKey(ECPublicKeySpec ecKeySpec) throws InvalidKeySpecException {
        super(ecKeySpec);
        if (!(ecKeySpec instanceof SM2PublicKeySpec)) {
            throw new InvalidKeySpecException("Must be SM2PublicKeySpec");
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
