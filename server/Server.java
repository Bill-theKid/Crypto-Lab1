import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.ArrayList;
import java.security.*;

class Server {

    private static final int PORT = 7791;
    private static KeyPair keyPair = null;
    private static ArrayList<Room> rooms = new ArrayList<>();
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
                new ServerThread(client).start();
            }
        }
    }

    public static Room getRoom(int index) {
        System.out.println("getting room");
        return rooms.get(index);
    }

    public static void addRoom(Room room) {
        rooms.add(room);
        System.out.println("New room created: " + room.getName());
    }

    public static void removeRoom(Room room) {
        rooms.remove(room);
        System.out.println("Room deleted: " + room.getName());
    }

    public static int numRooms() {
        return rooms.size();
    }

    public static String roomList() {
        String str = "";
        for(int i = 0; i < Server.numRooms(); i++) {
            str = str + i + ": " + rooms.get(i).getName() + "\n";
        }
        return str;
    }

    public static KeyPair getKeyPair() {
        return keyPair;
    }

    public static void populateUsers() throws Exception {
        File file = new File("users.txt");
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

    public static User getUser(String name, String password) throws Exception {
        for(int i = 0; i < users.size(); i++) {
            if(users.get(i).validLogin(name, password))
                return users.get(i);
        }
        return null;
    }
}