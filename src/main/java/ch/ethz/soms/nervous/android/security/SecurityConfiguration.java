package ch.ethz.soms.nervous.android.security;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import ch.ethz.soms.nervous.android.security.services.CustomSecuritySettings;

/**
 * Created by Kishore on 8/31/2015.
 * Singleton Pattern class to access Security Configuration Resources.
 */
public final class SecurityConfiguration extends CustomSecuritySettings {

    private static Context context;
    private static SecurityConfiguration securityConfiguration;
    private SSLSocketFactory sslSocketFactory;

    private SecurityConfiguration(Context context) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        super(context.getResources());
        this.sslSocketFactory = super.getCustomSSLSocketFactory();
    }

    /**
     * Get Custom <code>SSLSocketFactory</code> instance statically using pre-defined settings in Security-Configuration.XML file.
     * Since this is a singleton instance, resources will be accessed only once in apps lifecycle.
     * This can be used to make <code>HttpsUrlConnection</code> requests, by defining this SocketFactory to connection instance.
     * Example:
     * SSLSocketFactory customSSLSocketFactory = SecurityConfiguration.getSSLSocketFactoryInstance(context); // Throws Exceptions.
     * HttpsUrlConnection urlConnection = (HttpsUrlConnection) url.openConnection();
     * urlConnection.setSSLSocketFactory(customSSLSocketFactory);
     *
     * @param context
     * @return
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyManagementException
     * @throws KeyStoreException
     */
    public static SSLSocketFactory getSSLSocketFactoryInstance(Context context) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        checkConfiguration(context);
        return securityConfiguration.sslSocketFactory;
    }

    /**
     * Make Http requests directly using pre-defined settings in Security-Configuration.XML file.
     * @param context
     * @param url
     * @return
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyManagementException
     * @throws KeyStoreException
     */
    public static InputStream makeRequest(Context context, URL url) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        checkConfiguration(context);
        HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
        urlConnection.setSSLSocketFactory(securityConfiguration.sslSocketFactory);
        return urlConnection.getInputStream();
    }

    /**
     * Get Custom SSLSocket with pre-defined settings in Security-Configuration.XML file.
     * @param host
     * @param port
     * @return
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyManagementException
     * @throws KeyStoreException
     */
    public static Socket constructSSLSocket(String host, int port) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        checkConfiguration(context);
        return securityConfiguration.sslSocketFactory.createSocket(host, port);
    }

    /**
     * Get Custom SSLSocket with pre-defined settings in Security-Configuration.XML file.
     * Use SSLSocketFactory if this Socket has to initiated with different parameters.
     * @param inetAddress
     * @param port
     * @return
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyManagementException
     * @throws KeyStoreException
     */
    public static Socket constructSSLSocket(InetAddress inetAddress, int port) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        checkConfiguration(context);
        return securityConfiguration.sslSocketFactory.createSocket(inetAddress, port);
    }

    private static void checkConfiguration(Context context) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        if(securityConfiguration == null) {
            Log.d("CustomSecurity","Creating new SecurityConfiguration Instance.");
            securityConfiguration = new SecurityConfiguration(context);
        }
    }
}
