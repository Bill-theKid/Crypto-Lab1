import java.util.Base64;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class ServerThread extends Thread {

    private Socket client;
    private BufferedReader in;
    private PrintWriter out;
    private DataInputStream dataIn;
    private DataOutputStream dataOut;
    private KeyPair keyPair;
    private byte[] sessionKey;

    public ServerThread(Socket sock, KeyPair kp) throws Exception {
        client = sock;
        keyPair = kp;
        in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        out = new PrintWriter(client.getOutputStream(), true);
        dataIn = new DataInputStream(sock.getInputStream());
        dataOut = new DataOutputStream(sock.getOutputStream());
    }
    public void run() {
        try {
            // Put what server does here

            generateSessionKey();

            while(true) {
                String msg = in.readLine();
                echo(in.readLine());
            }

        } catch(Exception e) {
            System.out.println(e);
        }
    }

    public void echo(String msg) {
        out.println(msg);
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
            keyBytes = keyPair.getPublic().getEncoded();
            dataOut.writeInt(keyBytes.length);
            dataOut.write(keyBytes);

            System.out.println("Generating session key...");
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(clientPub, true);
            sessionKey = ka.generateSecret();
            System.out.println("Session key generated.");
            System.out.println(Base64.getEncoder().encodeToString(sessionKey));

        } catch(Exception e) {
            System.out.println(e);
        }
    }
}
