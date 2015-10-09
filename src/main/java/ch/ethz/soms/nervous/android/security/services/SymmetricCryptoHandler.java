package ch.ethz.soms.nervous.android.security.services;

/*
    Originally Authored by:
    Copyright (c) 2014 Scott Alexander-Bown
    Modified according to this application's usage.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */

import android.content.Context;
import android.content.res.Resources;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Implementation of Symmetric Key Cryptography (Designed for AES).
 * This can be used for Local data encryption. It takes in Data and PassKey as parameters,
 * but make sure to store the passkey securely.
 */
public abstract class SymmetricCryptoHandler {

    private String CRYPTO_MODE;      // Mode to Symmetric Cryptography.
    private String BLOCK_MODE;      // Mode to Symmetric Cryptography.
    private String PADDING_MODE;      // Mode to Symmetric Cryptography.
    private String CHARSET;                              // Use App's default Charset.
    private String HASH_ALGORITHM ;    // Hashing Algorithm.
    private String CRYPTO_ALGORITHM;

    public SymmetricCryptoHandler(Context context){
        setUpParameters(context.getResources());
    }

    private void setUpParameters(Resources resources){
        CRYPTO_MODE = resources.getString(R.string.MODE_CRYPTO);      // Mode to Symmetric Cryptography.
        BLOCK_MODE = resources.getString(R.string.MODE_BLOCK);      // Mode to Symmetric Cryptography.
        PADDING_MODE = resources.getString(R.string.MODE_PADDING);      // Mode to Symmetric Cryptography.
        CHARSET = "UTF-8";                             // Use App's default Charset.
        HASH_ALGORITHM = resources.getString(R.string.HASH_ALGORITHM);    // Hashing Algorithm.
        CRYPTO_ALGORITHM = CRYPTO_MODE + "/" + BLOCK_MODE + "/" + PADDING_MODE;
    }



    private final byte[] ivBytes = {                                                                    // Byte stream, that can be used for Hex conversion.
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00
    };


    /**
     * Generates <code>SecretKeySpec</code> from given Hash of password.
     * @param password used to generated key
     * @return HashKey of the password
     */
    private SecretKeySpec generateKey(final String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] bytes = password.getBytes(CHARSET);
        digest.update(bytes, 0, bytes.length);
        byte[] key = digest.digest();

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, CRYPTO_MODE);
        return secretKeySpec;
    }


    /**
     * Encrypt and encode message using 256-bit AES with key generated from password.
     *
     *
     * @param password used to generated key
     * @param message the thing you want to encrypt assumed String UTF-8
     * @return Base64 encoded CipherText
     * @throws GeneralSecurityException if problems occur during encryption
     */
    public String encrypt(final String password, String message)
            throws GeneralSecurityException {

        try {
            final SecretKeySpec key = generateKey(password);


            byte[] cipherText = encrypt(key, ivBytes, message.getBytes(CHARSET));

            //NO_WRAP is important as was getting \n at the end
            String encoded = Base64.encodeToString(cipherText, Base64.NO_WRAP);
            return encoded;
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * Encrypt using bytes and return cipher bytes.
     *
     * @param password used to generated key
     * @param bytes the thing you want to encrypt assumed String UTF-8
     * @return Base64 encoded CipherText
     * @throws GeneralSecurityException if problems occur during encryption
     */
    public byte[] encrypt(final String password, final byte[] bytes)
            throws GeneralSecurityException {

        try {
            final SecretKeySpec key = generateKey(password);

            byte[] cipherText = encrypt(key, ivBytes, bytes);

            return cipherText;
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }


    /**
     * More flexible AES encrypt that doesn't encode
     * @param key AES key typically 128, 192 or 256 bit
     * @param iv Initiation Vector
     * @param message in bytes (assumed it's already been decoded)
     * @return Encrypted cipher text (not encoded)
     * @throws GeneralSecurityException if something goes wrong during encryption
     */
    public byte[] encrypt(final SecretKeySpec key, final byte[] iv, final byte[] message)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(CRYPTO_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = cipher.doFinal(message);

        return cipherText;
    }


    /**
     * Decrypt and decode ciphertext using 256-bit AES with key generated from password
     *
     * @param password used to generated key
     * @param base64EncodedCipherText the encrpyted message encoded with base64
     * @return message in Plain text (String UTF-8)
     * @throws GeneralSecurityException if there's an issue decrypting
     */
    public String decrypt(final String password, String base64EncodedCipherText)
            throws GeneralSecurityException {

        try {
            final SecretKeySpec key = generateKey(password);
            byte[] decodedCipherText = Base64.decode(base64EncodedCipherText, Base64.NO_WRAP);

            byte[] decryptedBytes = decrypt(key, ivBytes, decodedCipherText);
            String message = new String(decryptedBytes, CHARSET);


            return message;
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * Decrypt bytes encryptes previously, using the same key.
     *
     * @param password used to generated key
     * @param cipherBytes the encrpyted message in bytes.
     * @return message in Plain text (String UTF-8)
     * @throws GeneralSecurityException if there's an issue decrypting
     */
    public byte[] decrypt(final String password, final byte[] cipherBytes)
            throws GeneralSecurityException {

        try {
            final SecretKeySpec key = generateKey(password);

            byte[] decryptedBytes = decrypt(key, ivBytes, cipherBytes);

            return decryptedBytes;
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }


    /**
     * More flexible AES decrypt that doesn't encode
     *
     * @param key AES key typically 128, 192 or 256 bit
     * @param iv Initiation Vector
     * @param decodedCipherText in bytes (assumed it's already been decoded)
     * @return Decrypted message cipher text (not encoded)
     * @throws GeneralSecurityException if something goes wrong during encryption
     */
    public byte[] decrypt(final SecretKeySpec key, final byte[] iv, final byte[] decodedCipherText)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(CRYPTO_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(decodedCipherText);
        return decryptedBytes;
    }


    /**
     * Converts byte array to hexidecimal useful for logging and fault finding
     * @param bytes
     * @return
     */
    private String bytesToHex(byte[] bytes) {
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}