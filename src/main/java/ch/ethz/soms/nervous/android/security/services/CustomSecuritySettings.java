package ch.ethz.soms.nervous.android.security.services;

import android.content.res.AssetManager;
import android.content.res.Resources;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import ch.ethz.soms.nervous.android.security.util.AdditionalKeyStoresSSLSocketFactory;

/**
 * Created by Kishore on 8/30/2015.
 */
public abstract class CustomSecuritySettings {

    private Resources resources;                                                        // The Application Context, to read Security Settings from Android's XML Resources.

    public CustomSecuritySettings(Resources resources) {
        this.resources = resources;
    }

    /**
     * Get Custom <code>SSLSocketFactory</code> instance statically using pre-defined settings in Security-Configuration.XML file.
     * Over-riding this method will prevent usage of Security-Configuration.XML's settings.
     * @return
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws KeyManagementException
     */
    public SSLSocketFactory getCustomSSLSocketFactory() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
       if(!resources.getBoolean(R.bool.USING_SELF_SIGNED_CERTIFICATES)){           // If not at all using self-signed certificates, which is a default setting,
                                                                                    // return CA only SSLSocket directly.
            return getCacertsSocketFactory();
        }
        else if(!resources.getBoolean(R.bool.USING_CA_CERTIFICATES)){               // Else if not using CA and using Self-Signed from previous condition,
                                                                                    // return Self-Signed certificate's SSLSocket.
            return getSelfSignedSocketFactory();
        }
        else{
            return getComplexSocketFactory();                                       // Else, using both of them, return this SSLSocket.
        }
    }

    /**
     * Get Android's default SSLSocketFactory.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     */
    private SSLSocketFactory getCacertsSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);

        return sslContext.getSocketFactory();
    }

    /**
     * Get SSLSocketFactory based on Local Keystore.
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws IOException
     * @throws CertificateException
     */
    private SSLSocketFactory getSelfSignedSocketFactory() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, IOException, CertificateException {
        AssetManager assetManager        = resources.getAssets();

        InputStream keyStoreInputStream = assetManager.open(resources.getString(R.string.LOCAL_KEY_STORE));
        KeyStore trustStore              = KeyStore.getInstance(resources.getString(R.string.LOCAL_KEY_STORE_TYPE));

        trustStore.load(keyStoreInputStream, resources.getString(R.string.LOCAL_KEY_STORE_PASSWORD).toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        return sslContext.getSocketFactory();
    }

    /**
     * Get Custom SSLSocketFactory. Check Against Android's default Trust Store for Certificates first, and if failed, fall back to Local Trust Store.
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws IOException
     * @throws CertificateException
     */
    private SSLSocketFactory getComplexSocketFactory() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        AssetManager assetManager        = resources.getAssets();

        InputStream keyStoreInputStream = assetManager.open(resources.getString(R.string.LOCAL_KEY_STORE));
        KeyStore localKeyStore              = KeyStore.getInstance(resources.getString(R.string.LOCAL_KEY_STORE_TYPE));

        localKeyStore.load(keyStoreInputStream, resources.getString(R.string.LOCAL_KEY_STORE_PASSWORD).toCharArray());

        return new AdditionalKeyStoresSSLSocketFactory(localKeyStore);
    }
}
