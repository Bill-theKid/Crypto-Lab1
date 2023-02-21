import java.net.*;
import java.io.*;

public class ClientThread extends Thread {
    private static Socket server;
    private static BufferedReader in;

    ClientThread(Socket server) throws IOException {
        this.server = server;
        in = new BufferedReader(new InputStreamReader(server.getInputStream()));
    }
    public void run() {
        try {
            while(true) {
                String messageIn = in.readLine();
                Client.printMsg(messageIn);
            }
        } catch(IOException e) {
            System.out.println("Lost connection to server.");
        } finally {
            try {
                in.close();
            } catch(IOException e) {
                e.printStackTrace();
            }
        }
    }
}