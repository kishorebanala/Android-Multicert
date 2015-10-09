package ch.ethz.soms.nervous.android.security;

import android.content.Context;

import java.security.GeneralSecurityException;

import javax.crypto.spec.SecretKeySpec;

import ch.ethz.soms.nervous.android.security.services.SymmetricCryptoHandler;

/**
 * Created by Kishore on 8/24/2015.
 */
public final class StaticCryptoHandler extends SymmetricCryptoHandler {

    private static StaticCryptoHandler cryptoHandler;

    private StaticCryptoHandler(Context context) {
        super(context);
    }

    public static String encrypt(Context context, String password, String data) throws GeneralSecurityException {
        checkHandler(context);
        return cryptoHandler.encrypt(password, data);
    }

    public static byte[] encrypt(Context context, final SecretKeySpec key, final byte[] iv, final byte[] message) throws GeneralSecurityException {
        checkHandler(context);
        return cryptoHandler.encrypt(key, iv, message);
    }

    public static byte[] encrypt(Context context, String password, byte[] bytes) throws GeneralSecurityException {
        checkHandler(context);
        return cryptoHandler.encrypt(password, bytes);
    }

    public static String decrypt(Context context, String password, String encrpytedData) throws GeneralSecurityException {
        checkHandler(context);
        return cryptoHandler.decrypt(password, encrpytedData);
    }

    public static byte[] decrypt(Context context, final SecretKeySpec key, final byte[] iv, final byte[] message) throws GeneralSecurityException {
        checkHandler(context);
        return cryptoHandler.decrypt(key, iv, message);
    }

    public static byte[] decrypt(Context context, String password, byte[] bytes) throws GeneralSecurityException {
        checkHandler(context);
        return cryptoHandler.decrypt(password, bytes);
    }

    /**
     *
     */
    private static void checkHandler(Context context){
        if(cryptoHandler == null){
            cryptoHandler = new StaticCryptoHandler(context);
        }
    }
 }
