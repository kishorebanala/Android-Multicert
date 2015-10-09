package ch.ethz.soms.nervous.android.security;

import android.content.Context;
import android.content.res.Resources;
import android.test.ActivityTestCase;

import com.android.kbanala.security.R;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLSocketFactory;

public class SecurityConfigurationTest extends ActivityTestCase{

	private final String VALID_TEST_URI = "https://wikipedia.org";
	private final String INVALID_TEST_URI = "https://localhost";

    Context context;
    Resources resources;

    @Before
    public void setUpObjects(){
        context = getActivity().getApplicationContext();
        resources = getActivity().getResources();
    }

    @Test
    public void testSecurityConfiguration(){
        // Check if Local Key Store is configured, if Self-Signed certificates are being used
        if(resources.getBoolean(R.bool.USING_SELF_SIGNED_CERTIFICATES)){
            Assert.assertNotNull(resources.getString(R.string.LOCAL_KEY_STORE_TYPE));
            Assert.assertNotNull(resources.getString(R.string.LOCAL_KEY_STORE));
            Assert.assertNotNull(resources.getString(R.string.LOCAL_KEY_STORE_PASSWORD));
        }

        // Check if at least one of the certificate values are true.
        if(!resources.getBoolean(R.bool.USING_CA_CERTIFICATES) && !resources.getBoolean(R.bool.USING_SELF_SIGNED_CERTIFICATES)){
            Assert.fail("should use at least one certificate type.");
        }

    }

	@Test
	public void testGetSSLSocketFactoryInstance() {
        try {
            SSLSocketFactory sslSocketFactory = SecurityConfiguration.getSSLSocketFactoryInstance(context);
            Assert.assertNotNull(sslSocketFactory);
        } catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyManagementException e) {
            Assert.fail("failed to obtain SSLSocketFactory.");
        }
    }

	@Test
	public void testMakeRequest() {
        if(!usingCACerts()){
            return;
        }
		try {
			URL url = new URL(VALID_TEST_URI);
			InputStream inputStream = SecurityConfiguration.makeRequest(context, url);
			Assert.assertNotNull(inputStream);
		} catch (MalformedURLException e) {
            Assert.fail("Invalid URL");
		} catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyManagementException e) {
            Assert.fail("Mis-configured Certificate.");
		}
	}

	@Test
	public void testMakeRequestFail() {
		try {
			URL url = new URL(INVALID_TEST_URI);
			InputStream inputStream = SecurityConfiguration.makeRequest(context, url);
			Assert.assertNull(inputStream);
		} catch (MalformedURLException e) {

		} catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyManagementException e) {

		}
	}

    private boolean usingCACerts(){
        if(resources.getBoolean(R.bool.USING_CA_CERTIFICATES)){
            return true;
        }
        return false;
    }
}
