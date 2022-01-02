package part2;

import part1.Util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
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

            } catch (InvalidKeyException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
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

        public void getFromKeyStore(String password) {
            try {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(new FileInputStream("cybr372.jks"), password.toCharArray());
                privateKey = (PrivateKey) ks.getKey("clientKey", password.toCharArray());
                publicKey = ks.getCertificate("clientKey").getPublicKey();
                servPublicKey = ks.getCertificate("serverKey").getPublicKey();
            } catch (Exception e) {
                e.printStackTrace();
            }
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

    /**
     * Commandline code to generate keys
     * keytool -genkeypair -alias server -keyalg RSA -keypass serverpassword -storepass badpassword -storetype jks -keystore cybr372.jks
     * keytool -genkeypair -alias client -keyalg RSA -keypass clientpassword -storepass badpassword -storetype jks -keystore cybr372.jks
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException, KeyStoreException, IOException {
        EchoClient client = new EchoClient();
        client.getFromKeyStore(args[0]);
            //Use keystore to generate keys
            client.startConnection("127.0.0.1", 4444);
            client.sendMessage("12345678");
            client.sendMessage("ABCDEFGH");
            client.sendMessage("87654321");
            client.sendMessage("HGFEDCBA");
            client.stopConnection();
    }
}
