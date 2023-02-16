import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;


public class Server extends Thread {

    private static final int PORT = 4545;

    public static void main(String[] args) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(Skip.sDHParameterSpec);
        KeyPair kp = kpg.genKeyPair();

        ServerSocket server = new ServerSocket(PORT);

        while(true) {
            Socket client = server.accept();
            System.out.println("client received: " + client.toString());
            new ServerThread(client).start();
        }
    }
}
