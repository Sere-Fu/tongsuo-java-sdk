/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class SM2SignatureParameters extends AlgorithmParametersSpi {
    private byte[] id;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof SM2SignatureParameterSpec)) {
            throw new InvalidParameterSpecException("Only SM2SignatureParameterSpec is supported");
        }
        id = ((SM2SignatureParameterSpec) paramSpec).getId().clone();
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            byte[] newId = NativeCrypto.asn1_read_octetstring(readRef);
            if (!NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.id = newId;
        } finally {
            NativeCrypto.asn1_read_free(readRef);
        }
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            engineInit(bytes);
        } else if (format.equals("RAW")) {
            id = bytes.clone();
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if (aClass != SM2SignatureParameterSpec.class) {
            throw new InvalidParameterSpecException(
                    "Incompatible AlgorithmParametersSpec class: " + aClass);
        }
        return (T) new SM2SignatureParameterSpec(id);
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        long cbbRef = 0;
        try {
            cbbRef = NativeCrypto.asn1_write_init();
            NativeCrypto.asn1_write_octetstring(cbbRef, this.id);
            return NativeCrypto.asn1_write_finish(cbbRef);
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbbRef);
            throw e;
        } finally {
            NativeCrypto.asn1_write_free(cbbRef);
        }
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            return engineGetEncoded();
        } else if (format.equals("RAW")) {
            return id.clone();
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    protected String engineToString() {
        return "Conscrypt SM2 Signature AlgorithmParameters";
    }

}
