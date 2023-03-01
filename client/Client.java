import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private static final int PORT = 7791;
    private static Socket server;
    private static SecretKey sessionKey;
    private static String algorithm;

    public static void main(String[] args) throws Exception {
        String option = args[1];
        algorithm = args[3];

        server = new Socket(InetAddress.getByName(args[0]), PORT);
        PrintWriter out = new PrintWriter(server.getOutputStream(), true);
        Scanner userIn = new Scanner(System.in);
        out.println(algorithm);

        // login
        System.out.println("Please Login");
        System.out.println("Username: ");
        out.println(userIn.nextLine());
        System.out.println("Password: ");
        out.println(userIn.nextLine());

        userIn.close();

        System.out.println("Generating Diffie-Hellman key pair...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(Skip.sDHParameterSpec);
        KeyPair keyPair = kpg.genKeyPair();

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
        PublicKey serverPub = kf.generatePublic(x509Spec); // yHan

        System.out.println("Generating session key...");
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(serverPub, true);
        byte[] secret = ka.generateSecret();
        System.out.println("Session key generated.");
        System.out.println(Base64.getEncoder().encodeToString(secret));

        KeySpec keyspec = null;
        SecretKeyFactory keyfactory = null;
        switch(algorithm) {
            case "AES":
                sessionKey = new SecretKeySpec(secret, 0, 32, "AES");
                break;
            case "DES":
                keyspec = new SecretKeySpec(secret, "DES");
                keyfactory = SecretKeyFactory.getInstance("DES");
                sessionKey = keyfactory.generateSecret(keyspec);
                break;
            case "DESede":
                keyspec = new SecretKeySpec(secret, "DESede");
                keyfactory = SecretKeyFactory.getInstance("DESede");
                sessionKey = keyfactory.generateSecret(keyspec);
                break;
        }

        System.out.println("Session Key generated.");

        switch(option) {
            case "send":
                out.println("send");
                send(args[2]);
                break;
            case "get":
                out.println("get");
                get(args[2]);
                break;
            default:
                System.out.println("Invalid Command: type 'send' or 'get'");
        }
    }

    public static void send(String filename) throws Exception {
        FileInputStream fileIn = new FileInputStream(filename);
        DataOutputStream dataOut = new DataOutputStream(server.getOutputStream());

        Cipher cipher1 = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        cipher1.init(Cipher.ENCRYPT_MODE, sessionKey);

        byte[] iv1 = cipher1.getIV();
        dataOut.writeInt(iv1.length); // Length of initialization vector, plain text.
        dataOut.write(iv1); // Actual initialization vector, plain text.

        byte[] input1 = new byte[64]; // Encrypt 64 byte blocks
        while (true) {
            int bytesRead = fileIn.read(input1);
            if (bytesRead == -1)
                break; // Check EOF.
            byte[] output1 = cipher1.update(input1, 0, bytesRead);
            if (output1 != null)
                dataOut.write(output1); // Write encrypted info to client.
        }
        byte[] output1 = cipher1.doFinal(); // Pad and flush
        if (output1 != null)
            dataOut.write(output1); // Write remaining to client.
        dataOut.close();
        fileIn.close();
    }

    public static void get(String filename) throws Exception {
        FileOutputStream fileOut = new FileOutputStream(filename);
        DataInputStream dataIn = new DataInputStream(server.getInputStream());

        // Read the initialization vector.
        int ivSize = dataIn.readInt();
        byte[] iv2 = new byte[ivSize];
        dataIn.readFully(iv2);
        IvParameterSpec ivps = new IvParameterSpec(iv2);

        // use Data Encryption Standard
        Cipher des = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        des.init(Cipher.DECRYPT_MODE, sessionKey, ivps);

        // Accept the encryped transmission, decrypt, and save in file.
        byte[] input = new byte[64];
        while (true) {
            int bytesRead = dataIn.read(input);
            if (bytesRead == -1)
                break;
            byte[] output2 = des.update(input, 0, bytesRead);
            if (output2 != null) {
                fileOut.write(output2);
                System.out.print(new String(output2));
            }
        }
        byte[] output2 = des.doFinal();
        if (output2 != null) {
            fileOut.write(output2);
            System.out.print(new String(output2));
        }
        fileOut.close();
        dataIn.close();
    }
}
