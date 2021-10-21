package part2;

import part2.Util.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    //  Required for encryption and decryption
    private static final String ALGORITHM = "RSA";
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEYSTORE_ALGORITHM = "pkcs12";

    //For the KeyStore
    private static final String PASSWORD = "badpassword";
    private static final String ALIAS = "cybr372";

    //The public and private key pair
    PublicKey clientPublicKey;
    PrivateKey clientPrivateKey;

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Obtains the public and private key pair from the KeyStore file provided.
     */
    public void getKeyPairFromStore() throws Exception{
        InputStream inputStream = EchoServer.class.getResourceAsStream("/cybr372.jks");

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_ALGORITHM);
        keyStore.load(inputStream, PASSWORD.toCharArray());
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(PASSWORD.toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, keyPassword);

        java.security.cert.Certificate certificate = keyStore.getCertificate(ALIAS);

        this.clientPublicKey = certificate.getPublicKey();
        this.clientPrivateKey = privateKeyEntry.getPrivateKey();
    }

    /**
     * Generates the public key from a Base64 encoded string.
     * @param base64PublicKey specified by user
     * @return public key created from string
     */
    public PublicKey getPublicKey(String base64PublicKey){
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));

            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            this.clientPublicKey = keyFactory.generatePublic(keySpec);
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return this.clientPublicKey;
    }

    /**
     * Generates the private key from a Base64 encoded string.
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
            this.clientPrivateKey = keyFactory.generatePrivate(keySpec);
        }catch(InvalidKeySpecException e){
            e.printStackTrace();
        }
        return this.clientPrivateKey;
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
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {

        this.clientPublicKey = getPublicKey(Base64.getEncoder().encodeToString(this.clientPublicKey.getEncoded()));
        this.clientPrivateKey = getPrivateKey(Base64.getEncoder().encodeToString(this.clientPrivateKey.getEncoded()));

        try {

//          Encrypting the string
            byte[] encryptedMessage = encrypt(msg, this.clientPublicKey);

            System.out.println("Client sending message to Server (cleartext): " + msg);
            System.out.println("Message sent as ciphertext: " + Util.bytesToHex(encryptedMessage));

            //Signing message
            byte[] signatureBytes = signMessage(this.clientPrivateKey, encryptedMessage);

            out.writeInt(encryptedMessage.length);
            out.write(encryptedMessage);
            out.write(signatureBytes);
            out.flush();

            int len = in.readInt();
            in.read(encryptedMessage);
            in.read(signatureBytes);

            //Decrypting the byte array
            String reply = decrypt(encryptedMessage, this.clientPrivateKey);

//            Checking if decrypted message is equal to original message
            if(!reply.equals(msg)){
                throw new IllegalArgumentException("Decrypted message does not equal original message");
            }

            System.out.println("Server returned plaintext: " + reply);

            //Verifying signature
            final boolean isValid = verifySignature(encryptedMessage, signatureBytes, this.clientPublicKey);

            if(!isValid){
                throw new IllegalArgumentException("Signatures do not match.");
            }
            System.out.println("Signatures match.");

            return reply;


        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    public static void main(String[] args) throws Exception {
        EchoClient client = new EchoClient();
        String keyStorePassword = PASSWORD;

        client.startConnection("127.0.0.1", 4444);


        try{
            if(args.length >= 1){
                if(args[0].equals(keyStorePassword)){
                    client.getKeyPairFromStore();
                    client.sendMessage("12345678");
                }
            }
        }catch (IllegalArgumentException e){
            e.printStackTrace();
        }

        client.stopConnection();
    }
}
