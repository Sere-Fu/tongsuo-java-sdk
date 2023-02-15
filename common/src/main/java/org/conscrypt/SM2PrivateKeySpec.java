package org.conscrypt;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;

public class SM2PrivateKeySpec extends ECPrivateKeySpec {

    public SM2PrivateKeySpec(BigInteger s) {
        super(s, SM2ParameterSpec.instance());
    }

    public SM2PrivateKeySpec(BigInteger s, SM2ParameterSpec params) {
        super(s, SM2ParameterSpec.instance());
    }

    @Override
    public ECParameterSpec getParams() {
        return SM2ParameterSpec.instance();
    }
}
