import java.net.*;
import java.io.*;

public class ServerThread extends Thread {

    private Socket server;

    public ServerThread(Socket sock) {
        server = sock;
    }
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(server.getInputStream()));
            PrintWriter out = new PrintWriter(server.getOutputStream(), true);

        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
