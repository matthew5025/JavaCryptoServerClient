import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Nathaniel on 21/1/2015.
 */
public class CryptoStuff {
    public static boolean verifySignature(byte[] file, byte[] signature, String publicKey) throws Exception {

        FileInputStream keyfis = new FileInputStream(publicKey);
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);

        keyfis.close();

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        byte[] sigToVerify = signature;

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);

        sig.update(file);

        boolean verifies = sig.verify(sigToVerify);

        return verifies;

    }

    public static byte[] generateHMAC(byte key[], byte message[]) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HMACSHA256");
        Mac mac = Mac.getInstance("HMACSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message);

        return hmac;

    }

    public static byte[] encryptAES(byte[] key, byte[] message, byte[] iv) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
        byte[] ciphertext = cipher.doFinal(message);
        return ciphertext;

    }

    public static boolean verifySignature(byte[] file, byte[] signature, byte[] publicKey) throws Exception {

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        byte[] sigToVerify = signature;

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);

        sig.update(file);

        boolean verifies = sig.verify(sigToVerify);

        return verifies;

    }

    public static byte[] encryptRSA(byte[] publicKey, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");


        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encryptedData = cipher.doFinal(message);

        return (encryptedData);


    }

    public static byte[] decryptRSA(String privateKeyPath, byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");


        FileInputStream keyfis = new FileInputStream(privateKeyPath);
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);

        keyfis.close();

        KeySpec priKeySpec = new PKCS8EncodedKeySpec(encKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey priKey = (RSAPrivateKey) keyFactory.generatePrivate(priKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        byte[] plainText = cipher.doFinal(cipherText);

        return (plainText);

    }
}
