package ch.ethz.soms.nervous.android.security;

import android.content.Context;

import ch.ethz.soms.nervous.android.security.services.SymmetricCryptoHandler;

/**
 * Created by Kishore on 9/3/2015.
 * Singleton class to Encrypt and Decrypt data.
 */
public class CryptoHandler extends SymmetricCryptoHandler{

    private static CryptoHandler cryptoHandler;

    private CryptoHandler(Context context) {
        super(context);
    }

    public static CryptoHandler getInstance(Context context){
        if(cryptoHandler == null){
            cryptoHandler = new CryptoHandler(context);
        }
        return cryptoHandler;
    }
}