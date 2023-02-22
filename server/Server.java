import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.ArrayList;
import java.security.*;

class Server {

    private static final int PORT = 7791;
    private static KeyPair keyPair = null;
    private static ArrayList<Room> rooms = new ArrayList<>();
    private static ArrayList<ServerThread> clients = new ArrayList<>();
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

    public static void log(String msg) {
        System.out.println(msg);
    }

    public void sendToAll(ServerThread client, String message) {
        message = client.getUser().getName() + ": " + message;
        for(int i = 0; i < clients.size(); i++) {
            if(clients.get(i).getUser().getName().equals(client.getUser().getName()))
                continue;
            else
                clients.get(i).send(message);
        }
    }

    public void sendToAll(String message) {
        for(int i = 0; i < clients.size(); i++)
            clients.get(i).send(message);
    }

    public void sendServerMsg(String message) {
        String serverMsg = "[SERVER] " + message;
        sendToAll(serverMsg);
    }

    public static Room getRoom(int index) {
        return rooms.get(index);
    }

    public static void addRoom(String name) {
        rooms.add(new Room(name));
        log("New room created: " + name);
    }

    public static void removeRoom(Room room) {
        rooms.remove(room);
        log("Room deleted: " + room.getRoomName());
    }

    public static int numRooms() {
        return rooms.size();
    }

    public static String roomList() {
        String str = "";
        for(int i = 0; i < Server.numRooms(); i++) {
            str = str + i + ": " + rooms.get(i).getRoomName() + "\n";
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
}