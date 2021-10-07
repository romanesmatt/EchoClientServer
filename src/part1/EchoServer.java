package part1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;


    //public and private keys as Base64 strings
    private static final String PUBLIC_KEY_STRING = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt2Tmt+qMc0iQHgu9529fKEWQHZEHKtUYu+dBZ+mkh8LdhbvdF90k3u/WrrHeES6UiMBhfZP4xneNStts3GI6b15mRcMfOPF6Lp6gFUdAFcUjab9iupdpj0NLNpHNiv2Zd/1uVNvgbGN1qbKrbhbm05lW+XSzgl9OWiZZG32aONWK3NDNgB0AshtJVeGgy3xUuYDJsB+g71ge3uYgrT7L89MnVDrD9lon4w2cAxHqN252elJCR+8PFPAjSB5zKY6h2fwZbMCBbVQTZFbKM8/YkiMEAtdCI+qrLI0JumaIkbmuZQV7RwMUnquvUoYTaTuG0sk1XHVo8+RIzOWvuhtsFwIDAQAB";
    private static final String PRIVATE_KEY_STRING = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3ZOa36oxzSJAeC73nb18oRZAdkQcq1Ri750Fn6aSHwt2Fu90X3STe79ausd4RLpSIwGF9k/jGd41K22zcYjpvXmZFwx848XounqAVR0AVxSNpv2K6l2mPQ0s2kc2K/Zl3/W5U2+BsY3WpsqtuFubTmVb5dLOCX05aJlkbfZo41Yrc0M2AHQCyG0lV4aDLfFS5gMmwH6DvWB7e5iCtPsvz0ydUOsP2WifjDZwDEeo3bnZ6UkJH7w8U8CNIHnMpjqHZ/BlswIFtVBNkVsozz9iSIwQC10Ij6qssjQm6ZoiRua5lBXtHAxSeq69ShhNpO4bSyTVcdWjz5EjM5a+6G2wXAgMBAAECggEACAtHGW37JnsrumCP7LWaL/PKnZliCbBUsOdu4SNCuV2J+rm+/5AaIoG9bZUyfGlEIcluy9JB9kDHubqEcRg35dmlvZNWYNifCNiKyrzd6faKFj7uHgB1MBW4OvnAUTfj9oa0/YJVdRi20EeoNKwcZYm2P69+yF94FEqn3AKxaIuzLBd6vIp6JJU3xRCuSGRpdVSe1DovnToWWS8tpwUeOEM32GY+MADQSHCzh+AbtNNEWFcU3jthR04d23VVH3lqZ6OsMgPfBniKEugz4sjP+JrGE404722MIvAHfd2PLXFB3WrRCSC5KS6uPQpjOp8jWW1t9rdBjcpovua31WVTMQKBgQD68WDg6ZfOkLOpD7TQM75sa7Vvza3+2LAVwaM1V046rCjx0NdgNhQx7D/CeWycLcsw2yubWlYuWLkwchZwa2/r3ITREpUbmV6zDgzBImCaK5Fo4fKVR73QRy3SVQ4XMvGFR9GNu731SKM/NQqBKfkcSU+WnhaxTrJH5mUEPD8qxwKBgQC7FwlzuIRExjlD5c7906azjY46arC7PhL6LFeGqhLdemVfBOV3+i8YsZB47/NlT79h4R6qwxIt9Gb3v2oUHiKfurDz/sq/fTt3tgMXoUNHpk+o86iUZpgkSaWELgRPLj1smmQ7oH60MZhDOSr973b+h8Uzt7MVB1WeYn8Mzb3kMQKBgH6bU96F3GKKnSpZ00cMJDH9ca/z3KpsVwLTDG34G278tzexv0g6YJwDbvPGYWa2sAJ5QZoCzOJbPyvTE8EqY3BjdNsq/fHLwnyiRQsYNhbyjk2VWde5N2oiz1qEMTTBLhupbW+N3jwnpr1YHHGoZJfB4RbDsf1JECe4dRTa9J+3AoGAQ25xLLFTkwoy96LrsRbI3axml+1+V25vHpY+0b2Y4RTNVqsIHe8hbHALV1t8yYYtv5SJHhkDA2c0eZUXIbse1Z1PTBIId24mseX7RVgNTNTHn2h62UoFCgc1TefcC8Hpx6v59nfJUx8Q9yGyuiXGKMU8sYBDXo/vLw/nJPE+wPECgYASLIrgvMj14WHiIZjueFEjk4XA08+0Ko/76k9X3TOvDUVA2TrZeY3DaSCKFVCzPjknrX4hFUKmy2esNj5c+/YOoI9JU/b/qi29OrgDhAFb9FrIsZ006edALyxaHg6tpQC6DDGS6YX8wT45XGi5B2PwdfyF87eZWBIL1Uw3fwbtpA==";

    //  Required for encryption and decryption
    private static final String ALGORITHM = "RSA";
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    //The public and private key pair
    PublicKey serverPublicKey;
    PrivateKey serverPrivateKey;

    public EchoServer() throws NoSuchAlgorithmException {
    }


    /**
     * Generates the public and private key pair.
     */
    public void generateKeys(){
        try{
            //Generating key pair (both public and private)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();

            keyPairGenerator.initialize(2048, secureRandom);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            //Printing the public key
            System.out.println();
            System.out.println();
            System.out.println("Public key string: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }

    }

    /**
     * Encrypts the given string and returns it as a byte array.
     *
     * @param data string
     * @param publicKey
     * @return byte array of encrypted string
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] encrypt(String data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] stringToEncrypt = data.getBytes(StandardCharsets.UTF_8);

        return cipher.doFinal(stringToEncrypt);
    }

    /**
     * Decrypts the given byte array and returns it as a string.
     *
     * @param data byte array
     * @param privateKey
     * @return decrypted byte array as a string
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     */
    public String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] arrToDecrypt = cipher.doFinal(data);

        return new String(arrToDecrypt);
    }

    /**
     * Obtains the public key specified by the user.
     * @param base64PublicKey specified by user
     * @return public key created from string
     */
    public PublicKey getPublicKey(String base64PublicKey){
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            this.serverPublicKey = keyFactory.generatePublic(keySpec);
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return this.serverPublicKey;
    }


    /**
     * Obtains the private key.
     * @param base64PrivateKey private key encoded as a Base64 string
     * @return private key created from string
     */
    public PrivateKey getPrivateKey(String base64PrivateKey){
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try{
            keyFactory = KeyFactory.getInstance(ALGORITHM);
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        try{
            this.serverPrivateKey = keyFactory.generatePrivate(keySpec);
        }catch(InvalidKeySpecException e){
            e.printStackTrace();
        }
        return this.serverPrivateKey;
    }

    /**
     * Signs the message sent by the Server For The Client.
     * @param PrivateKey private key specified by server
     * @param encryptedBytes encrypted message as a byte array
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public byte[] signMessage(PrivateKey PrivateKey, byte[] encryptedBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        System.out.println("Signing message...");
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(PrivateKey);
        signature.update(encryptedBytes);
        byte[] signatureBytes = signature.sign();
        System.out.println("Message signed.");

        return signatureBytes;
    }

    /**
     * Verifies the signature that came with the message.
     * @param decryptedBytes
     * @param signatureBytes
     * @param publicKey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean verifySignature(byte[] decryptedBytes, byte[] signatureBytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        System.out.println("Verifying signature...");

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(decryptedBytes);

        return signature.verify(signatureBytes);
    }

    /**
     * Prompts the user to specify the public key that will be used for encryption and signature
     * @return user input
     * @throws IOException
     */
    public String specifyKey() throws IOException {
        System.out.println("Please specify public key for the Client: ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String input = br.readLine();
        br.close();

        return input;
    }

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws IOException {

        String userPublicKey = specifyKey();
        this.serverPublicKey = getPublicKey(userPublicKey);
        this.serverPrivateKey = getPrivateKey(PRIVATE_KEY_STRING);

        System.out.println("Server is running...");


        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());

            int len = in.readInt();
            byte[] signatureBytes = new byte[len]; //
            byte[] data = new byte[len];
            int numBytes;

            while ((numBytes = in.read(data)) != -1) {
                in.read(signatureBytes);

                // decrypt data
                String msg = decrypt(data, this.serverPrivateKey);
                System.out.println("Server received cleartext from Client: " + msg);
                //verify signature
                boolean isValid = verifySignature(data, signatureBytes, this.serverPublicKey);

                if(!isValid){
                    throw new IllegalArgumentException("Signatures do not match.");
                }
                System.out.println("Signatures match.");

                // encrypt response (this is just the decrypted data re-encrypted)

                byte[] strToEncrypt = encrypt(msg, this.serverPublicKey);
                System.out.println("Message to be sent back to Client (cleartext):" + msg);
                System.out.println("Message sent as ciphertext: "+Util.bytesToHex(strToEncrypt));
                signatureBytes = signMessage(this.serverPrivateKey, strToEncrypt);

                out.writeInt(strToEncrypt.length);
                out.write(strToEncrypt);
                out.write(signatureBytes);
                out.flush();

//                msg = "";
//                signatureBytes = null;
//                strToEncrypt = null;

            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        } catch (NoSuchPaddingException
                | NoSuchAlgorithmException
                | IllegalBlockSizeException
                | InvalidKeyException
                | BadPaddingException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

    }


    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        EchoServer server = new EchoServer();
        server.generateKeys();
        server.start(4444);
        server.stop();
    }

}



