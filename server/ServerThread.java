import java.util.Base64;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class ServerThread extends Thread {

    private Socket client;
    private String username;
    private BufferedReader in;
    private PrintWriter out;
    private RoomHandler room;
    private static final String COMMANDS = "Type /join [room #] to join a room\nType /create [room name] to create a room\nType /rooms to display open rooms\nType /help to display this message again";
    private byte[] sessionKey;

    public ServerThread(Socket sock) throws Exception {
        client = sock;
        in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        out = new PrintWriter(client.getOutputStream(), true);
    }

    ServerThread(Socket sock, String name) throws IOException {
        client = sock;
        username = name;
        in = new BufferedReader(new InputStreamReader(client.getInputStream()));
        out = new PrintWriter(client.getOutputStream(), true);
    }

    public void run() {
        try {

            generateSessionKey();

            username = in.readLine();
            send(Server.roomList() + COMMANDS);
            while(true) {
                String messageIn = in.readLine();
                parseInput(messageIn);
            }
        } catch(IOException e) {
            room.sendServerMsg(username + " disconnected.");
            Server.log("Client disconnected: " + client.toString());
        } finally {
            out.close();
            try {
                in.close();
            } catch(IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void generateSessionKey() {
        try {

            DataInputStream dataIn = new DataInputStream(client.getInputStream());
            DataOutputStream dataOut = new DataOutputStream(client.getOutputStream());

            System.out.println("Receiving public key...");
            byte[] keyBytes = new byte[dataIn.readInt()];
            dataIn.readFully(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
            PublicKey clientPub = kf.generatePublic(x509Spec);

            System.out.println("Sending public key...");
            keyBytes = Server.getKeyPair().getPublic().getEncoded();
            dataOut.writeInt(keyBytes.length);
            dataOut.write(keyBytes);

            System.out.println("Generating session key...");
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(Server.getKeyPair().getPrivate());
            ka.doPhase(clientPub, true);
            sessionKey = ka.generateSecret();
            System.out.println("Session key generated.");
            System.out.println(Base64.getEncoder().encodeToString(sessionKey));

        } catch(Exception e) {
            System.out.println(e);
        }
    }

    public void parseInput(String input) {
        if(input.charAt(0) == '/') {
            String[] subStr = input.split(" ", 2);
            switch(subStr[0]) {
                case "/join":
                    try {
                        if(room != null) {
                            RoomHandler prev = room;
                            Server.getRoom(Integer.parseInt(subStr[1])).addClient(this);
                            room = Server.getRoom(Integer.parseInt(subStr[1]));
                            prev.removeClient(this);
                            send("Joined " + room.getRoomName());
                        } else {
                            Server.getRoom(Integer.parseInt(subStr[1])).addClient(this);
                            room = Server.getRoom(Integer.parseInt(subStr[1]));
                            send("Joined " + room.getRoomName());
                        }
                    } catch(IndexOutOfBoundsException e) {
                        send("Invalid room number");
                    }
                    break;
                case "/create":
                    try {
                        Server.addRoom(subStr[1]);
                        if(room != null) {
                            room.removeClient(this);
                        }
                        Server.getRoom(Server.numRooms() - 1).addClient(this);
                        room = Server.getRoom(Server.numRooms() - 1);
                        send("Joined " + room.getRoomName());
                    } catch(ArrayIndexOutOfBoundsException e) {
                        send("command syntax: /create RoomName");
                    }
                    break;
                case "/rooms":
                    send(Server.roomList());
                    break;
                case "/help":
                    send(COMMANDS);
                    break;
                default:
                    send("Invalid command");
            }
        }
        else {
            try {
                room.sendToAll(this, input);
            } catch(NullPointerException e) {
                send("Not currently in room");
            }
        }
    }

    public void send(String message) {
        out.println(message);
    }
    
    public String getUsername() {
        return username;
    }
}
