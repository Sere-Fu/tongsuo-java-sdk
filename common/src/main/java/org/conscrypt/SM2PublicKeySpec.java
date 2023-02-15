package org.conscrypt;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

public class SM2PublicKeySpec extends ECPublicKeySpec {

    public SM2PublicKeySpec(ECPoint w) {
        super(w, SM2ParameterSpec.instance());
    }

    public SM2PublicKeySpec(ECPoint w, SM2ParameterSpec params) {
        super(w, params);
    }

    @Override
    public ECParameterSpec getParams() {
        return SM2ParameterSpec.instance();
    }
}
