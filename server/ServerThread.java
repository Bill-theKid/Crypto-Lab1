// Server thread class
// Clients are accepted by the main thread and a new thread is 
// opened on the server to handle each client

import java.util.Base64;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServerThread extends Thread {
    
    private Socket client;
    private User user;
    private DataInputStream dataIn;
    private DataOutputStream dataOut;
    private byte[] secret;
    private SecretKey sessionKey;
    private String algorithm;

    ServerThread(Socket client) throws IOException {
        this.client = client;
        dataIn = new DataInputStream(client.getInputStream());
        dataOut = new DataOutputStream(client.getOutputStream());
    }

    public void run() {
        try {

            // init io
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            PrintWriter out = new PrintWriter(client.getOutputStream());

            // login
            algorithm = in.readLine();
            String userIn = in.readLine();
            String passIn = in.readLine();
            user = Server.getUser(userIn, passIn);
            if(user == null) {
                out.println("Login Failed");
                client.close();
            }
            out.println("Login Successful");

            // init keys
            generateSessionKey();

            // receive file
            FileOutputStream fileOut = new FileOutputStream("output.txt");
            // Read the initialization vector.
            int ivSize = dataIn.readInt();
            byte[] iv1 = new byte[ivSize];
            dataIn.readFully(iv1);
            IvParameterSpec ivps = new IvParameterSpec(iv1);

            // init cipher
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

            fileOut.flush();
            fileOut.close();
            dataOut.flush();

            // send file
            FileInputStream fileIn = new FileInputStream("inputfile");

            Cipher cipher1 = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            cipher1.init(Cipher.ENCRYPT_MODE, sessionKey);

            byte[] iv2 = cipher1.getIV();
            dataOut.writeInt(iv2.length); // Length of initialization vector, plain text.
            dataOut.write(iv2); // Actual initialization vector, plain text.

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

            fileIn.close();
            dataOut.close();
            dataIn.close();


        } catch(Exception e) {
            e.printStackTrace();
        }


    }

    public void generateSessionKey() {
        try {
            System.out.println("Receiving public key...");
            byte[] keyBytes = new byte[dataIn.readInt()];
            dataIn.readFully(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
            PublicKey clientPub = kf.generatePublic(x509Spec);

            System.out.println("Sending public key...");
            keyBytes = Server.getKeyPair().getPublic().getEncoded();
            dataOut.writeInt(keyBytes.length);
            dataOut.write(keyBytes);

            System.out.println("Generating session key...");
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(Server.getKeyPair().getPrivate());
            ka.doPhase(clientPub, true);
            secret = ka.generateSecret();
            System.out.println("Session secret generated.");
            System.out.println(Base64.getEncoder().encodeToString(secret));

            KeySpec keyspec = new SecretKeySpec(secret, algorithm);
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(algorithm);
            sessionKey = keyfactory.generateSecret(keyspec);
            System.out.println("Session Key generated.");

        } catch(Exception e) {
            System.out.println(e);
        }
    }
}
