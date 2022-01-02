package part1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey servPublicKey;


    /**
     * Create the public and private keys.
     */
    public void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair pair = keyPairGen.generateKeyPair();

        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        System.out.println("Keys generated");
        System.out.println("Public Key\n\t" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }

    /**
     * User input public key
     */
    public void enterPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        Scanner s = new Scanner(System.in);
        System.out.println("Please enter a public key:");
        String publicKeyInput = s.nextLine();
        X509EncodedKeySpec destPubK = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyInput.getBytes()));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        servPublicKey = factory.generatePublic(destPubK);
    }

    /**
     * Setup the two way streams.
     *
     * @param ip   the address of the server
     * @param port port used by the server
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
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) {
        try {
            System.out.println("Client sending cleartext: " + msg);
            byte[] cipherText = "".getBytes(UTF_8);
            String decryptedData = "";

            try {
                Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                encryptCipher.init(Cipher.ENCRYPT_MODE, servPublicKey);

                cipherText = encryptCipher.doFinal(msg.getBytes(UTF_8));

            } catch (InvalidKeyException | IllegalBlockSizeException |NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
                e.printStackTrace();
            }

            Signature sign = null;
            try {
                sign = Signature.getInstance("SHA256withRSA");
                sign.initSign(privateKey);
                sign.update(cipherText);
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            System.out.println("Client sending ciphertext: " + Util.bytesToHex(cipherText));
            byte[] signMsg = sign.sign();

            out.write(signMsg);
            out.write(cipherText);
            out.flush();

            in.read(signMsg);
            in.read(cipherText);

            //Verify signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(servPublicKey);
            signature.update(cipherText);

            if (signature.verify(signMsg)) {

                try {
                    Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

                    decryptedData = new String(decryptCipher.doFinal(cipherText), UTF_8);

                } catch (InvalidKeyException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
                    e.printStackTrace();
                }
                System.out.println("Server returned cleartext: " + decryptedData);
                return decryptedData;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
        return "Signature could not verify!";
    }

    /**
     * Close down our streams.
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("Error upon closing!");
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        EchoClient client = new EchoClient();
        client.generateKeys();
        client.enterPublicKey();
        client.startConnection("127.0.0.1", 4444);
        client.sendMessage("12345678");
        client.sendMessage("ABCDEFGH");
        client.sendMessage("87654321");
        client.sendMessage("HGFEDCBA");
        client.stopConnection();
    }
}
