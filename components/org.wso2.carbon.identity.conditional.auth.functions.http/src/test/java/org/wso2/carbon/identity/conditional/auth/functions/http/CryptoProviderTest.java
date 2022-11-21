/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoProviderTest implements InternalCryptoProvider {
    private static final String ALGO = "AES";

    /*
     * Method to generate a secret key for AES algorithm with a given secret key.
     */
    private static Key generateKey(String secretKey) throws Exception
    {
        Key key = new SecretKeySpec(secretKey.getBytes(), ALGO);
        return key;
    }

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        try {
            return this.encryptInternal(cleartext,"TheBestSecretKey");
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        try {
            return this.decryptInternal(ciphertext,"TheBestSecretKey");
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider,
                          boolean returnSelfContainedCipherText) throws CryptoException {

        try {
            return this.encryptInternal(cleartext,"TheBestSecretKey");
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }


    private byte[] encryptInternal(byte[] data, String secretKey) throws Exception {

        Key key = generateKey(secretKey);
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data);
        return encVal;
    }

    private byte[] decryptInternal(byte[] encryptedData, String secretKey) throws Exception {

        Key key = generateKey(secretKey);
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decValue = c.doFinal(encryptedData);
        return decValue;
    }
}
