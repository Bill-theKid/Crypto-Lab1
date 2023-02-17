import java.util.Base64;
import java.util.Scanner;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class Client {

    private static final int PORT = 4545;
    private static String host;
    private static byte[] sessionKey;

    public static void main(String[] args) throws Exception {
        try {
            // String host = args[0];
            String host = "127.0.0.1";
        } catch(Exception e) {
            System.out.println(e);
            System.exit(0);
        }

        try {
            Socket client = new Socket(host, PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            PrintWriter out = new PrintWriter(client.getOutputStream());
            DataInputStream dataIn = new DataInputStream(client.getInputStream());
            DataOutputStream dataOut = new DataOutputStream(client.getOutputStream());

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

            client.close();

        } catch(UnknownHostException e) {
            System.out.println("Invalid IP");
        }
        
    }

    public static void generateSessionKey() {

    }
}
