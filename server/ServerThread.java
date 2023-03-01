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

            // get algorithm choice from client
            algorithm = in.readLine();

            // login
            String userIn = in.readLine();
            String passIn = in.readLine();
            user = Server.getUser(userIn, passIn);
            if(user == null) {
                out.println("Login Failed");
                client.close();
            }
            out.println("Login Successful");

            // init keys
            try {
                // Diffie-Hellman
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
    
                // convert key for selected encryption algorithm
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
    
            } catch(Exception e) {
                System.out.println(e);
            }

            // receive operation choice from client
            String option = in.readLine();
            switch(option) {
                case "send":
                    get();
                    break;
                case "get":
                    send();
                    break;
                default:
                    System.out.println("error");
                    break;
            }

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    public void send() {
        try {
            // preset server file to send
            FileInputStream fileIn = new FileInputStream("serverfile.flag");

            // init cipher
            Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);

            byte[] iv = cipher.getIV();
            System.out.println("sending iv length");
            dataOut.writeInt(iv.length);
            dataOut.write(iv);

            byte[] input = new byte[64];
            while (true) {
                int bytesRead = fileIn.read(input);
                if (bytesRead == -1)
                    break;
                byte[] output = cipher.update(input, 0, bytesRead);
                if (output != null)
                    dataOut.write(output);
            }

            byte[] output = cipher.doFinal();
            if (output != null)
                dataOut.write(output);

            fileIn.close();
            dataOut.close();
            dataIn.close();

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    public void get() {
        try {
            FileOutputStream fileOut = new FileOutputStream("output" + user.getName() + ".txt");

            int ivSize = dataIn.readInt();
            byte[] iv = new byte[ivSize];
            dataIn.readFully(iv);
            IvParameterSpec ivps = new IvParameterSpec(iv);

            // init cipher
            Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivps);

            byte[] input = new byte[64];
            while (true) {
                int bytesRead = dataIn.read(input);
                if (bytesRead == -1)
                    break;
                byte[] output = cipher.update(input, 0, bytesRead);
                if (output != null) {
                    fileOut.write(output);
                    System.out.print(new String(output));
                }
            }
            byte[] output = cipher.doFinal();
            if (output != null) {
                fileOut.write(output);
                System.out.print(new String(output));
            }

            fileOut.close();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
