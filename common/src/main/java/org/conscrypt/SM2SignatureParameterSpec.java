/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.security.spec.AlgorithmParameterSpec;

public class SM2SignatureParameterSpec implements AlgorithmParameterSpec {
    private byte[] id;

    public SM2SignatureParameterSpec(byte[] id) {
        this.id = id.clone();
    }

    public byte[] getId() {
        return id.clone();
    }
}
