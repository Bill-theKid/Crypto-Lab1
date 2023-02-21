import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.util.Base64;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class Client {
    public static void main(String[] args) throws Exception {
        String host = args[0];
        int port = 7791;
        Scanner input = new Scanner(System.in);
        Socket server;

        try {
            server = new Socket(InetAddress.getByName(host), port);

            generateSessionKey(server);

            PrintWriter out = new PrintWriter(server.getOutputStream(), true);
            new ClientThread(server).start();

            System.out.print("Enter Username: ");
            while(true) {
                String messageOut = input.nextLine();
                out.println(messageOut);
            }
        } catch(UnknownHostException e) {
            System.err.println("Error: Address not found.");
        }
    }

    public static void printMsg(String message) {
        System.out.println(message);
    }

    public static void generateSessionKey(Socket server) throws Exception {
        DataInputStream dataIn = new DataInputStream(server.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(server.getOutputStream());

        // Create a Diffie-Hellman key pair (public and private).
        System.out.println("Generating Diffie-Hellman key pair...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(Skip.sDHParameterSpec);
        KeyPair keyPair = kpg.genKeyPair( );  // xLuke & yLuke

        // Send our public key to host.
        System.out.println("Sending public key...");
        byte[] keyBytes = keyPair.getPublic().getEncoded();
        dataOut.writeInt(keyBytes.length);  // length yLuke in bytes
        dataOut.write(keyBytes);  // send yLuke as byte string

        // Accept public key from host (length, key in bytes).
        System.out.println("Receiving public key...");
        keyBytes = new byte[dataIn.readInt()];  // read length of xHan
        dataIn.readFully(keyBytes); // read xHan as string of bytes
        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
        PublicKey serverPub = kf.generatePublic(x509Spec);  //yHan

        // Calculate the secret session key.
        System.out.println("Generating session key...");
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init( keyPair.getPrivate());  // using xLuke
        ka.doPhase(serverPub, true); // init withyHan
        byte[] sessionKey = ka.generateSecret();  // Shared secret key.
        System.out.println("Session key generated.");
        System.out.println(Base64.getEncoder().encodeToString(sessionKey));
    }
}
