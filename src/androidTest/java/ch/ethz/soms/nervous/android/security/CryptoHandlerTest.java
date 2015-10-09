package ch.ethz.soms.nervous.android.security;

import android.content.Context;
import android.test.ActivityTestCase;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;

/**
 * Created by Kishore on 9/4/2015.
 */
public class CryptoHandlerTest extends ActivityTestCase{

    Context context;
    CryptoHandler cryptoHandler;

    @Before
    public void setUpObjects(){
        context = getActivity().getApplicationContext();
        cryptoHandler = CryptoHandler.getInstance(context);
        Assert.assertNotNull(cryptoHandler);
    }

    @Test
    public void testEncryptDecrypt(){

        String TEST_PASS = "changeit";
        String TEST_MSG = "Hello World!";

        String encryptedMsg = null;
        try {
            encryptedMsg = cryptoHandler.encrypt(TEST_PASS, TEST_MSG);
            Assert.assertNotNull(encryptedMsg);
        }catch (GeneralSecurityException e){
            Assert.fail("error occurred during encrypt");
            e.printStackTrace();
        }

        String messageAfterDecrypt = null;
        try {
            messageAfterDecrypt = cryptoHandler.decrypt(TEST_PASS, encryptedMsg);
            Assert.assertNotNull(messageAfterDecrypt);

        }catch (GeneralSecurityException e){
            Assert.fail("error occurred during Decrypt");
            e.printStackTrace();
        }

        if (!TEST_MSG.equals(messageAfterDecrypt)){
            Assert.fail("messages don't match after encrypt and decrypt");
        }
    }

    @Test
    public void testEncryptDecryptFail(){

        String TEST_PASS_VALID = "changeit";
        String TEST_PASS_INVALID = "fakepassword";
        String TEST_MSG = "Hello World!";

        String encryptedMsg = null;
        try {
            encryptedMsg = cryptoHandler.encrypt(TEST_PASS_VALID, TEST_MSG);
            Assert.assertNotNull(encryptedMsg);
        }catch (GeneralSecurityException e){
            Assert.fail("error occurred during encrypt");
            e.printStackTrace();
        }

        String messageAfterDecrypt = null;
        try {
            messageAfterDecrypt = cryptoHandler.decrypt(TEST_PASS_INVALID, encryptedMsg);

        }catch (GeneralSecurityException e){
        }

        if (TEST_MSG.equals(messageAfterDecrypt)){
            Assert.fail("messages match after encrypt and decrypt with different passwords, shouldn't match in " +
                    "this condition.");
        }
    }

    @Test
    public void testEncryt(){

        String TEST_PASS = "password";
        String message = "hello world";

        try {
            String encryptedMsg = cryptoHandler.encrypt(TEST_PASS, message);

        }catch (GeneralSecurityException e){
            Assert.fail("error occurred during encrypt");
            e.printStackTrace();
        }
    }

    @Test
    public void testDecrpyt(){

        String TEST_PASS = "password";
        String encryptedMsg = "2B22cS3UC5s35WBihLBo8w==";

        try {
            String messageAfterDecrypt = cryptoHandler.decrypt(TEST_PASS, encryptedMsg);

        }catch (GeneralSecurityException e){
            Assert.fail("error occurred during Decrypt");
            e.printStackTrace();
        }
    }
}
