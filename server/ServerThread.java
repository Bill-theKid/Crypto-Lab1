import java.net.*;
import java.io.*;

public class ServerThread extends Thread {

    private Socket client;
    private BufferedReader in;
    private PrintWriter out;

    public ServerThread(Socket sock) throws Exception {
        client = sock;
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        PrintWriter out = new PrintWriter(client.getOutputStream(), true);
    }
    public void run() {
        try {
            // Put what server does here
            while(true) {
                echo(in.readLine());
            }

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public void echo(String msg) {
        out.println(msg);
    }
}
