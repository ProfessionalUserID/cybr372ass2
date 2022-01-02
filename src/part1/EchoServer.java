package part1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey clientPublicKey;

    public KeyPair serverKPGen() throws NoSuchAlgorithmException {
        KeyPairGenerator kPGen = KeyPairGenerator.getInstance("RSA");
        kPGen.initialize(2048);
        KeyPair serverKP = kPGen.generateKeyPair();
        System.out.println("Base64 Encoded Server Public Key:\n" + Base64.getEncoder().encodeToString
                (serverKP.getPublic().getEncoded()) +" \n");
        privateKey = serverKP.getPrivate();
        publicKey = serverKP.getPublic();
        return serverKP;
    }

    /**
     * This method asks user for a specified Public Key as a destination (to encrypt the message)
     */
    public void returnPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        Scanner s = new Scanner(System.in);
        System.out.println("Please enter a public key:");
        String publicKeyInput = s.nextLine();
        X509EncodedKeySpec destPubK = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyInput.getBytes()));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        clientPublicKey = factory.generatePublic(destPubK);
    }

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws NoSuchAlgorithmException, NoSuchPaddingException {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());

            Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decrypt.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] sig = new byte[256];
            byte[] data = new byte[256];
            int signatureBytes;
            int dataBytes;

            while (((signatureBytes = in.read(sig)) != -1) && (dataBytes = in.read(data)) != -1) {
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(clientPublicKey);
                signature.update(data);
                if (signature.verify(sig)) {
                    String done = new String(decrypt.doFinal(data), "UTF-8");

                    Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    encrypt.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                    byte[] cipherText = encrypt.doFinal(done.getBytes());
                    System.out.println("Encryption successful! \n" + Base64.getEncoder().encodeToString(cipherText));

                    Signature sign = null;
                    try {
                        sign = Signature.getInstance("SHA256withRSA");
                        sign.initSign(privateKey);
                        sign.update(cipherText);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }

                    byte[] signMsg = sign.sign();
                    out.write(signMsg);
                    out.write(cipherText);
                    out.flush();
                } else {
                    System.err.println("Signature key incorrect!");
                    System.exit(1);
               }
            }
            stop();
        } catch (IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | SignatureException e) {
            System.out.println(e.getMessage());
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

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        EchoServer server = new EchoServer();
        server.serverKPGen();
        server.returnPublicKey();
        server.start(4444);
    }

}



