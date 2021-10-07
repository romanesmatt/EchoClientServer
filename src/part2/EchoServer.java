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

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    //  Required for encryption and decryption
    private static final String ALGORITHM = "RSA";
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEYSTORE_ALGORITHM = "JCEKS";

    //For the KeyStore
    private static final String PASSWORD = "badpassword";
    private static final String ALIAS = "cybr372";

    //The public and private key pair
    PublicKey serverPublicKey;
    PrivateKey serverPrivateKey;


     /**
     * Obtains the public and private key pair from the KeyStore file provided.
     */
    public void getKeyPairFromStore() throws Exception{
        System.out.println("Getting KeyPair from KeyStore...");

        InputStream inputStream = EchoServer.class.getResourceAsStream("/cybr372.jks");

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(inputStream, PASSWORD.toCharArray());
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(PASSWORD.toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, keyPassword);

        java.security.cert.Certificate certificate = keyStore.getCertificate(ALIAS);

        this.serverPublicKey = certificate.getPublicKey();
        this.serverPrivateKey = privateKeyEntry.getPrivateKey();
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
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws IOException {

        this.serverPublicKey = getPublicKey(Base64.getEncoder().encodeToString(this.serverPublicKey.getEncoded()));
        this.serverPrivateKey = getPrivateKey(Base64.getEncoder().encodeToString(this.serverPrivateKey.getEncoded()));

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
                System.out.println("Sending message back to Client (cleartext):" + msg);
                System.out.println("Server sending ciphertext: "+ Util.bytesToHex(strToEncrypt));
                signatureBytes = signMessage(this.serverPrivateKey, strToEncrypt);

                out.writeInt(strToEncrypt.length);
                out.write(strToEncrypt);
                out.write(signatureBytes);
                out.flush();

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

    public static void main(String[] args) throws Exception {

        EchoServer server = new EchoServer();

        String keyStorePassword = PASSWORD;

        try{
            if(args.length >= 1){
                if(args[0].equals(keyStorePassword)){
                    server.getKeyPairFromStore();
                    server.start(4444);
                }
            }
        }catch (IOException e){
            e.printStackTrace();
        }
    }

}



