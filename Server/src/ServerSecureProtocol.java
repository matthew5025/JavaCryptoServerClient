import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by Nathaniel on 21/1/2015.
 */
public class ServerSecureProtocol {
    private static final int WAITING = 0;
    private static final int SENTSERVERHELLO = 1;
    private static final int STARTCLIENTAUTH = 2;
    private static final int STARTDHEXCHANGE = 3;

    private static final int STARTCIPHERCHANGE = 4;

    private static final int ENCRYPTIONOK = 5;
    private static String modp2048Modulas = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    private final BigInteger modp2048Base = BigInteger.valueOf(2);
    public boolean encryptionDone = false;
    protected byte[] sharedSecret;
    private int state = WAITING;
    private String publicKeyPath = "sPublic";
    private String privateKeyPath = "sPrivate";
    private String signedPublicKeyPath = "sigSPub";
    private String rootPublicKeyPath = "rPublic";
    private byte[] clientPublicKey;
    private byte[] sessionKey;
    private KeyAgreement serverKeyAgree;
    private long counter = 0;

    public String processInput(String theInput) throws Exception {
        String theOutput = null;

        if (state == WAITING) {
            {

                if (theInput == null) {

                    File crlFile = new File("crlOld.txt");
                    BufferedReader in = new BufferedReader(new FileReader(crlFile));
                    String version = in.readLine();


                    return "Connection Established. CRL:"+version;
                }
                if (theInput.startsWith("ClientHello:::")) {

                    String crlCheck = theInput.split(":::")[1];

                    File publicKeyFile = new File(publicKeyPath);
                    byte[] publicKeyBytes = org.apache.commons.io.FileUtils.readFileToByteArray(publicKeyFile);
                    String encodedPublicKey = org.apache.commons.codec.binary.Base64.encodeBase64String(publicKeyBytes);
                    File signedPublicKeyFile = new File(signedPublicKeyPath);
                    byte[] signedPublicKeyBytes = org.apache.commons.io.FileUtils.readFileToByteArray(signedPublicKeyFile);
                    String encodedSignedPublicKey = org.apache.commons.codec.binary.Base64.encodeBase64String(signedPublicKeyBytes);



                    if(crlCheck.equals("CRLOK")){
                        theOutput = "ServerHello:::" + encodedPublicKey + ":::" + encodedSignedPublicKey + ":::ServerHelloDone";
                        state = SENTSERVERHELLO;

                    }else if (crlCheck.equals("CRLOLDER")){
                        FileInputStream crlFIS = new FileInputStream("crl.txt");
                        byte[] CRL = new byte[crlFIS.available()];
                        crlFIS.read(CRL);

                        crlFIS.close();

                        String crlEncoded = Base64.encodeBase64String(CRL);

                        FileInputStream crlsFIS = new FileInputStream("sCRL");
                        byte[] CRLS = new byte[crlsFIS.available()];
                        crlsFIS.read(CRLS);

                        crlsFIS.close();

                        String crlsEncoded = Base64.encodeBase64String(CRLS);

                        theOutput = "ServerHello:::" + encodedPublicKey + ":::" + encodedSignedPublicKey +":::" +crlEncoded +":::"+crlsEncoded+":::ServerHelloDone";
                        state = SENTSERVERHELLO;

                    }else if(crlCheck.equals("CRLNEWER")){
                        System.out.println("Checking CRL received from server.");

                        byte[] crl = Base64.decodeBase64(theInput.split(":::")[2]);
                        byte[] crlSig = Base64.decodeBase64(theInput.split(":::")[3]);

                        if(!CryptoStuff.verifySignature(crl,crlSig,rootPublicKeyPath)){
                            throw new Exception("Did you just try to send me an invalid CRL?????????");
                        }

                        File crlFile = new File("crl.txt");
                        BufferedReader in = new BufferedReader(new FileReader(crlFile));
                        int version = Integer.parseInt(in.readLine());

                        String receivedCRL = new String(crl);

                        int receivedCRLVersion = Integer.parseInt(receivedCRL.substring(0,1));

                        if(receivedCRLVersion > version){
                            System.out.println("Received CRL is valid! Writing to file...");
                            FileOutputStream output = new FileOutputStream(new File("crl.txt"));
                            IOUtils.write(crl, output);
                        }else{
                            throw new Exception("I asked for a NEWER version of the CRL man!");
                        }

                    }



                } else {
                    theOutput = "Unexpected message";
                }

            }
        } else if (state == SENTSERVERHELLO) {
            if (theInput.startsWith("Certificate:::") && theInput.endsWith("CertificateExchangeDone")) {

                String b64pubKey = theInput.split(":::")[1];
                String b64pubKeySig = theInput.split(":::")[2];

                byte[] pubKey = org.apache.commons.codec.binary.Base64.decodeBase64(b64pubKey);

                byte[] pubKeySig = org.apache.commons.codec.binary.Base64.decodeBase64(b64pubKeySig);

                boolean isVerified = CryptoStuff.verifySignature(pubKey, pubKeySig, rootPublicKeyPath);

                if (!isVerified) {
                    throw new Exception("Client public key verification failed!");
                }

                System.out.println("Client public key verified.");
                System.out.println("Checking CRL...");

                byte[] encoded = Files.readAllBytes(Paths.get("crlOld.txt"));
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


                System.out.println("Status: Client public key received and verified with CRL.");
                clientPublicKey = pubKey;

                state = STARTCLIENTAUTH;

                SecureRandom random = SecureRandom.getInstanceStrong();
                byte rand[] = new byte[1854];
                random.nextBytes(rand);


                sessionKey = rand;


                byte[] message = CryptoStuff.encryptRSA(clientPublicKey, rand);

                String payload = Base64.encodeBase64String(message);

                String signature = Base64.encodeBase64String(CryptoStuff.signMessage(privateKeyPath, message));

                theOutput = "StartServerClientAuth:::" + payload + ":::" + signature + ":::ServerSessionDone";


            } else {
                return null;
            }

        } else if (state == STARTCLIENTAUTH) {
            if (theInput.startsWith("StartClientServerAuth:::") && theInput.endsWith(":::ClientSessionDone")) {

                byte[] cipherText = Base64.decodeBase64(theInput.split(":::")[1]);

                byte[] plainText = CryptoStuff.decryptRSA(privateKeyPath, cipherText);

                System.out.println(DatatypeConverter.printHexBinary(plainText));


                if (!Arrays.equals(sessionKey, plainText)) {
                    throw new Exception("Session key not equal!");
                }


                    byte[] dhParm = DatatypeConverter.parseHexBinary(modp2048Modulas);

                    BigInteger modp2048Mod = new BigInteger(1, dhParm);

                DHParameterSpec dhParameterSpec = new DHParameterSpec(modp2048Mod, modp2048Base);

                    KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
                serverKpairGen.initialize(dhParameterSpec);
                    KeyPair serverKpair = serverKpairGen.generateKeyPair();

                    System.out.println("Initialization DH ...");
                    serverKeyAgree = KeyAgreement.getInstance("DH");
                    serverKeyAgree.init(serverKpair.getPrivate());

                    byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();

                    String encryptedDH = Base64.encodeBase64String(CryptoStuff.encryptRSA(clientPublicKey, serverPubKeyEnc));


                    state = STARTDHEXCHANGE;
                    theOutput = "ServerKeyExchange:::" + encryptedDH + ":::ServerKeyExchangeDone";


            } else {
                theOutput = null;
            }
        } else if (state == STARTDHEXCHANGE) {
            if (theInput.startsWith("ClientKeyExchange:::") && theInput.endsWith("ClientKeyExchangeDone")) {
                byte[] cipherText = Base64.decodeBase64(theInput.split(":::")[1]);
                byte[] plainText = CryptoStuff.decryptRSA(privateKeyPath, cipherText);

                KeyFactory serverKeyFactory = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(plainText);

                PublicKey clientPubKey = serverKeyFactory.generatePublic(x509KeySpec);

                serverKeyAgree.doPhase(clientPubKey, true);

                sharedSecret = serverKeyAgree.generateSecret();

                System.out.println("KEY: " + Base64.encodeBase64String(sharedSecret));

                SecureRandom random = SecureRandom.getInstanceStrong();

                byte rand[] = new byte[2048];
                random.nextBytes(rand);


                String hmacMessage = Base64.encodeBase64String(CryptoStuff.generateHMAC(sharedSecret, rand));

                theOutput = "ChangeCipherSpec:::" + Base64.encodeBase64String(rand) + ":::" + hmacMessage + ":::ServerDone";

                System.out.println(Base64.encodeBase64String(sessionKey));

                state = STARTCIPHERCHANGE;
            } else {
                return null;
            }
        } else if (state == STARTCIPHERCHANGE) {
            if (theInput.startsWith("ChangeCipherSpec:::") && theInput.endsWith(":::ClientDone")) {
                byte[] revRand = Base64.decodeBase64(theInput.split(":::")[1]);
                byte[] revHmac = Base64.decodeBase64(theInput.split(":::")[2]);


                byte[] compHmac = CryptoStuff.generateHMAC(sharedSecret, revRand);

                if (Arrays.equals(revHmac, compHmac)) {
                    state = ENCRYPTIONOK;
                    encryptionDone = true;

                } else {
                    throw new Exception("HMAC Verification Failed!");
                }
            }
        } else if (state == ENCRYPTIONOK) {
            byte[] key = ArrayUtils.addAll(sharedSecret, ByteBuffer.allocate(Long.BYTES).putLong(counter).array());

            byte[] genKey = CryptoStuff.generateHMAC(sessionKey, key);

            int offset = (int) (Math.abs((sessionKey[0]) + counter) % (sessionKey.length - 16));

            byte[] iv = Arrays.copyOfRange(sessionKey, offset, 16 + offset);

            String cipherText = theInput.split(":::")[0];
            byte[] hmac = Base64.decodeBase64(theInput.split(":::")[1]);

            byte[] calHMAC = CryptoStuff.generateHMAC(genKey, cipherText.getBytes());

            if(!Arrays.equals(hmac,calHMAC)){
                throw new Exception("Message has ben tampered with.");
            }



            byte[] bCipherText = Base64.decodeBase64(cipherText);
            byte[] plainText = CryptoStuff.decryptAES(genKey, bCipherText, iv);
            counter++;
            System.out.println("Plaintext: "+new String(plainText));
            theOutput = "";
        }
        return theOutput;
    }

}
