import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.ArrayList;
import java.security.*;

class Server {

    private static final int PORT = 7791;
    private static KeyPair keyPair = null;
    private static ArrayList<User> users = new ArrayList<>();

    public static void main(String[] args) throws Exception {

        populateUsers();

        System.out.println("Generating Diffie-Hellman key pair...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(Skip.sDHParameterSpec);
        keyPair = kpg.genKeyPair();

        try (ServerSocket server = new ServerSocket(PORT)) {
            System.out.println("Server opened at " + InetAddress.getLocalHost());
            System.out.println("Awaiting client connections...");

            while(true) {
                Socket client = server.accept();
                System.out.println("Client connected: " + client.toString());
                new ServerThread(client).start(); // send incoming client to new thread
            }
        }
    }

    public static KeyPair getKeyPair() {
        // returns DH Key Pair
        return keyPair;
    }

    public static void populateUsers() throws FileNotFoundException {
        // read user data from file and load into memory
        File file = new File("users.db");
        Scanner input = new Scanner(file, "utf-8");
        for(int i = 0; i < 10; i++) {
            users.add(new User());
            users.get(i).setName(input.nextLine());
            users.get(i).setPassword(input.nextLine());
        }
        input.close();
    }

    public static ArrayList<User> getUsers() {
        return users;
    }

    public static User getUser(String name, String password) {
        // select user from table
        for(int i = 0; i < users.size(); i++) {
            if(users.get(i).validLogin(name, password))
                return users.get(i);
        }
        return null;
    }
}