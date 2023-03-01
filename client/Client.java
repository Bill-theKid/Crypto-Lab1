import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class Client {

    private static final int PORT = 7791;
    private static String host;
    private static DataInputStream dataIn;
    private static DataOutputStream dataOut;
    private static byte[] secret;
    private static SecretKey sessionKey;
    private static String algorithm;

    public static void main(String[] args) throws Exception {
        host = args[0];
        Scanner input = new Scanner(System.in);
        Socket server;

        try {
            server = new Socket(InetAddress.getByName(host), PORT);

            PrintWriter out = new PrintWriter(server.getOutputStream(), true);
            new ClientThread(server).start();

            System.out.println("Choose an encryption algorithm:\n(Input corresponding number)\n1. DES\n2. AES\n3. DESede");
            String algoChoice = input.nextLine();
            out.println(algoChoice);
            generateSessionKey(server, Integer.parseInt(algoChoice));

            ClientThread.initEncrypt();

            while(true) {
                String messageOut = input.nextLine();

                if(messageOut.equals("/quit")) {
                    input.close();
                    System.exit(0);
                }

                send(messageOut);
            }
        } catch(UnknownHostException e) {
            System.err.println("Error: Address not found.");
        }
        input.close();
    }

    public static SecretKey getSessionKey() {
        return sessionKey;
    }

    public static String getAlgorithm() {
        return algorithm;
    }

    public static void generateSessionKey(Socket server, int algo) throws Exception {
        try {
            System.out.println("Generating Diffie-Hellman key pair...");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(Skip.sDHParameterSpec);
            KeyPair keyPair = kpg.genKeyPair( );

            System.out.println("Sending public key...");
            byte[] keyBytes = keyPair.getPublic().getEncoded();
            DataOutputStream dataOut = new DataOutputStream(server.getOutputStream());
            dataOut.writeInt(keyBytes.length);
            dataOut.write(keyBytes);

            System.out.println("Receiving public key...");
            DataInputStream dataIn = new DataInputStream(server.getInputStream());
            keyBytes = new byte[dataIn.readInt()];
            dataIn.readFully(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
            PublicKey serverPub = kf.generatePublic(x509Spec);  //yHan

            System.out.println("Generating session key...");
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init( keyPair.getPrivate());
            ka.doPhase(serverPub, true);
            secret = ka.generateSecret();
            System.out.println("Session key generated.");
            System.out.println(Base64.getEncoder().encodeToString(secret));

            switch(algo) {
                case 1:
                    algorithm = "DES";
                    break;
                case 2:
                    algorithm = "AES";
                    break;
                case 3:
                    algorithm = "DESede";
                    break;
            }
            System.out.println("Algorithm set.");

            KeySpec keyspec = new SecretKeySpec(secret, algorithm);
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(algorithm);
            sessionKey = keyfactory.generateSecret(keyspec);
            System.out.println("Session Key generated.");

        } catch(Exception e) {
            System.out.println(e);
        }
    }

    public static void send(String message) {
        byte[] data = message.getBytes();

        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);  

            byte[] output = cipher.doFinal(data);
            dataOut.write(output);
            dataOut.flush();
        } catch(Exception e) {
            System.out.println(e);
        }

    }

    public static void receive() throws Exception {
        byte[] data = dataIn.readAllBytes();

        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, Client.getSessionKey());

            byte[] output = cipher.doFinal(data);
            System.out.println(output.toString());
        } catch(Exception e) {
            System.out.println("receive error");
        }
    }
}
