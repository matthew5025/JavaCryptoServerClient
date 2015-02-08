import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.kohsuke.rngom.parse.host.Base;
import org.mozilla.javascript.EcmaError;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by Nathaniel on 21/1/2015.
 */
public class ClientSecureProtocol {
    private static final int WAITING = 0;
    private static final int SENTCLIENTHELLO = 1;
    private static final int SENTCLIENTCERT = 2;
    private static final int SENTCLIENTAUTH = 3;
    private static final int DHKEYEXCHANGEDONE = 4;

    private static final int ENCRYPTIONDONE = 5;
    public boolean isEncrypted = false;
    protected byte[] sharedSecret;
    private int state = WAITING;
    private String rootPublicKeyPath = "rPublic";
    private String publicKeyPath = "cPublic";
    private String signedPublicKeyPath = "sigCPub";
    private String privateKeyPath = "cPrivate";
    private byte[] serverPublicKey;

    private byte[] sessionKey;

    private long counter = 0;

    private boolean crlOld = false;

    public String processInput(String theInput) throws Exception {
        String theOutput = null;

        if (state == WAITING) {
            {

                if (theInput.startsWith("Connection Established.")) {

                    String crlVersion = theInput.split(":")[1];
                    File crlFile = new File("crlOld.txt");
                    BufferedReader in = new BufferedReader(new FileReader(crlFile));
                    String version = in.readLine();

                    int serverCRL = Integer.parseInt(crlVersion);

                    int clientCRL = Integer.parseInt(version);

                    if (serverCRL == clientCRL){
                        System.out.println("We have a up to date CRL.");
                        theOutput = "ClientHello:::CRLOK";
                        state = SENTCLIENTHELLO;

                    }else if (serverCRL > clientCRL){
                        System.out.println("We have and outdated CRL. Will request for an updated version.");
                        theOutput = "ClientHello:::CRLOLDER";
                        crlOld = true;
                        state = SENTCLIENTHELLO;

                    }else if(clientCRL > serverCRL){

                        System.out.println("Server has an older CRL. We will now send ours as we're kind folks.");

                        FileInputStream crlFIS = new FileInputStream("crl.txt");
                        byte[] CRL = new byte[crlFIS.available()];
                        crlFIS.read(CRL);

                        crlFIS.close();

                        String crlEncoded = Base64.encodeBase64String(CRL);

                        FileInputStream crlsFIS = new FileInputStream("crl.txt");
                        byte[] CRLS = new byte[crlsFIS.available()];
                        crlsFIS.read(CRLS);

                        crlsFIS.close();

                        String crlsEncoded = Base64.encodeBase64String(CRLS);

                        theOutput = "ClientHello:::CRLNEWER:::"+crlEncoded+":::"+crlsEncoded+":::CRLEXCHANGEDONE";


                        state = SENTCLIENTHELLO;

                    }


                }

            }
        } else if (state == SENTCLIENTHELLO) {
            if (theInput.startsWith("ServerHello") && theInput.endsWith("ServerHelloDone")) {


                if(crlOld){

                    System.out.println("Checking CRL received from server.");

                    byte[] crl = Base64.decodeBase64(theInput.split(":::")[3]);
                    byte[] crlSig = Base64.decodeBase64(theInput.split(":::")[4]);

                  if(!CryptoStuff.verifySignature(crl,crlSig,rootPublicKeyPath)){
                      throw new Exception("Did you just try to send me an invalid CRL?????????");
                  }

                    File crlFile = new File("crlOld.txt");
                    BufferedReader in = new BufferedReader(new FileReader(crlFile));
                    int version = Integer.parseInt(in.readLine());

                    String receivedCRL = new String(crl);

                    int receivedCRLVersion = Integer.parseInt(receivedCRL.substring(0,1));

                    if(receivedCRLVersion > version){
                        System.out.println("Received CRL is valid! Writing to file...");
                        FileOutputStream output = new FileOutputStream(new File("newCRL.txt"));
                        IOUtils.write(crl, output);
                    }else{
                        throw new Exception("I asked for a NEWER version of the CRL man!");
                    }

                }


                System.out.println("Received server public key! Verifying with RootCA...");
                String b64pubKey = theInput.split(":::")[1];
                String b64pubKeySig = theInput.split(":::")[2];

                byte[] pubKey = org.apache.commons.codec.binary.Base64.decodeBase64(b64pubKey);

                byte[] pubKeySig = org.apache.commons.codec.binary.Base64.decodeBase64(b64pubKeySig);

                boolean isVerified = CryptoStuff.verifySignature(pubKey, pubKeySig, rootPublicKeyPath);

                if (isVerified) {
                    System.out.println("Server public key verified.");
                    System.out.println("Checking CRL...");

                    byte[] encoded = Files.readAllBytes(Paths.get("crl.txt"));
                    String CRL = new String(encoded);

                    String [] crlList = CRL.split("START");

                    if(crlList.length>0){
                        for(String CCRL : crlList){
                            CCRL = CCRL.replaceAll("\r\n","");
                            if(CCRL.equals(b64pubKeySig)){
                                throw new Exception("Key REVOKED!");
                            }
                        }
                    }
                    System.out.println("Server public key received and verified with CRL.");

                    serverPublicKey = pubKey;

                    File publicKeyFile = new File(publicKeyPath);
                    byte[] publicKeyBytes = org.apache.commons.io.FileUtils.readFileToByteArray(publicKeyFile);
                    String encodedPublicKey = org.apache.commons.codec.binary.Base64.encodeBase64String(publicKeyBytes);
                    File signedPublicKeyFile = new File(signedPublicKeyPath);
                    byte[] signedPublicKeyBytes = org.apache.commons.io.FileUtils.readFileToByteArray(signedPublicKeyFile);
                    String encodedSignedPublicKey = org.apache.commons.codec.binary.Base64.encodeBase64String(signedPublicKeyBytes);

                    System.out.println("Now Sending our key for the server to verify.");
                    System.out.println("The server will then start identity verification. This may take a long time.");


                    theOutput = "Certificate:::" + encodedPublicKey + ":::" + encodedSignedPublicKey + ":::CertificateExchangeDone";
                    state = SENTCLIENTCERT;
                } else {
                    throw new Exception("Bad certificate");
                }
            } else {
                return null;
            }
        } else if (state == SENTCLIENTCERT) {
            if (theInput.startsWith("StartServerClientAuth:::") && theInput.endsWith(":::ServerSessionDone")) {

                System.out.println("Key exchange completed. Now verifying server identity. This may take a long time.");

                byte[] cipherText = Base64.decodeBase64(theInput.split(":::")[1]);

                byte[] signature = Base64.decodeBase64(theInput.split(":::")[2]);

                if (!CryptoStuff.verifySignature(cipherText, signature, serverPublicKey)) {
                    throw new Exception("Signature of received message is not valid!");
                }

                byte[] plainText = CryptoStuff.decryptRSA(privateKeyPath, cipherText);

                ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(plainText, 0, Long.BYTES));

                long serverTime = bb.getLong();

                if (serverTime < System.currentTimeMillis() + 30000 && serverTime > System.currentTimeMillis() - 30000) {
                    System.out.println("Server identity verified. Now authenticating ourselves with the server. . .");

                    String payload = Base64.encodeBase64String(CryptoStuff.encryptRSA(serverPublicKey, plainText));

                    byte[] time = ByteBuffer.allocate(Long.BYTES).putLong(System.currentTimeMillis()).array();

                    byte rand[] = Arrays.copyOfRange(plainText, Long.BYTES, plainText.length);


                    sessionKey = rand;

                    byte[] bytes = new byte[1854];

                    System.arraycopy(time, 0, bytes, 0, time.length);
                    System.arraycopy(rand, 0, bytes, time.length, rand.length);
                    theOutput = "StartClientServerAuth:::" + payload + ":::ClientSessionDone";

                    state = SENTCLIENTAUTH;


                } else {
                    throw new Exception("Time difference between client and server is too wide.");
                }

            } else {
                return null;
            }
        } else if (state == SENTCLIENTAUTH) {

            if (theInput.startsWith("ServerKeyExchange:::") && theInput.endsWith(":::ServerKeyExchangeDone")) {
                System.out.println("Server has verified our identity! Now starting DH for master key exchange. . .");

                byte[] cipherText = Base64.decodeBase64(theInput.split(":::")[1]);
                byte[] plainText = CryptoStuff.decryptRSA(privateKeyPath, cipherText);

                KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(plainText);
                PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

                DHParameterSpec dhParamSpec = ((DHPublicKey) serverPubKey).getParams();

                KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
                clientKpairGen.initialize(dhParamSpec);
                KeyPair clientKpair = clientKpairGen.generateKeyPair();
                KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
                clientKeyAgree.init(clientKpair.getPrivate());

                byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();

                String encryptedDH = Base64.encodeBase64String(CryptoStuff.encryptRSA(serverPublicKey, clientPubKeyEnc));


                state = DHKEYEXCHANGEDONE;
                theOutput = "ClientKeyExchange:::" + encryptedDH + ":::ClientKeyExchangeDone";

                clientKeyAgree.doPhase(serverPubKey, true);
                sharedSecret = clientKeyAgree.generateSecret();

                System.out.println("Master Key negotiated.");


            } else {
                return null;
            }
        } else if (state == DHKEYEXCHANGEDONE) {
            if (theInput.startsWith("ChangeCipherSpec:::") && theInput.endsWith(":::ServerDone")) {

                System.out.println("Server has informed us to prepare to start encryption.");

                System.out.println("We will now check the validity of the master key. . .");

                byte[] revHmac = Base64.decodeBase64(theInput.split(":::")[1]);

                byte[] compHmac = CryptoStuff.generateHMAC(sharedSecret, sessionKey);


                if (Arrays.equals(revHmac, compHmac)) {

                    System.out.println("Master key verification OK!");

                    byte[] iv = Arrays.copyOfRange(sessionKey, 0, 16);

                    byte encSession[] = CryptoStuff.encryptAES(sharedSecret, sessionKey, iv);

                    String out = Base64.encodeBase64String(encSession);
                    theOutput = "ChangeCipherSpec:::" + out + ":::ClientDone";

                    System.out.println("Informing server we will now start encryption.");

                    state = ENCRYPTIONDONE;
                    isEncrypted = true;
                } else {
                    throw new Exception("HMAC Verification Failed!");
                }

            }
        } else if (state == ENCRYPTIONDONE) {
            byte[] key = ArrayUtils.addAll(sharedSecret, ByteBuffer.allocate(Long.BYTES).putLong(counter).array());

            int offset = (int) (Math.abs((sessionKey[0]) + counter) % (sessionKey.length - 16));

            byte[] iv = Arrays.copyOfRange(sessionKey, offset, 16 + offset);

            String encrypted = Base64.encodeBase64String(CryptoStuff.encryptAES(key, theInput.getBytes(), iv));

            String hmac = Base64.encodeBase64String(CryptoStuff.generateHMAC(key,encrypted.getBytes()));

            theOutput = encrypted+":::"+hmac;
            counter++;
        }

        return theOutput;
    }

}
