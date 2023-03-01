// receives incoming messages

import java.net.*;
import java.io.*;
import javax.crypto.*;

public class ClientThread extends Thread {
    private static BufferedReader in;
    private static DataInputStream dataIn;
    private static SecretKey sessionKey;
    private static String algo;

    ClientThread(Socket server) throws IOException {
        in = new BufferedReader(new InputStreamReader(server.getInputStream()));
        dataIn = new DataInputStream(server.getInputStream());
    }
    public void run() {

        try {
            while(sessionKey == null) {
                System.out.println(in.readLine());
            }
            in.close();
            while(true) {
                receive();
            }
        } catch(Exception e) {
            System.out.println(e);
        }
    }

    public static void initEncrypt() {
        sessionKey = Client.getSessionKey();
        algo = Client.getAlgorithm();
    }

    public static void receive() throws Exception {
        byte[] data = dataIn.readAllBytes();

        try {
            Cipher cipher = Cipher.getInstance(algo + "/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, Client.getSessionKey());

            byte[] output = cipher.doFinal(data);
            System.out.println(output.toString());
        } catch(Exception e) {
            System.out.println("receive error");
        }
    }
}