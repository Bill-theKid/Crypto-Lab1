// Server thread class
// Clients are accepted by the main thread and a new thread is 
// opened on the server to handle each client

import java.util.Base64;
import java.util.ArrayList;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServerThread extends Thread {
    
    private Socket client;
    private User user;
    private BufferedReader in;
    private PrintWriter out;
    private DataInputStream dataIn;
    private DataOutputStream dataOut;
    private Room room;
    private static final String COMMANDS = "Type /join [room #] to join a room\nType /create [room name] to create a room\nType /rooms to display open rooms\nType /help to display this message again";
    private byte[] secret;
    private SecretKey sessionKey;

    ServerThread(Socket client) throws IOException {
        this.client = client;
        in = new BufferedReader(new InputStreamReader(client.getInputStream()));
        out = new PrintWriter(client.getOutputStream(), true);
        dataIn = new DataInputStream(client.getInputStream());
        dataOut = new DataOutputStream(client.getOutputStream());
    }

    // ServerThread(Socket client, User user) throws IOException {
    //     this.client = client;
    //     this.user = user;
    //     in = new BufferedReader(new InputStreamReader(client.getInputStream()));
    //     out = new PrintWriter(client.getOutputStream(), true);
    // }

    public void run() {
        try {
            generateSessionKey();

            send("Choose an encryption algorithm:\n(Input corresponding number)\n1. DES\n2. AES");
            int algoChoice = Integer.parseInt(in.readLine());
            setAlgo(algoChoice);

            String userIn;
            String passIn;
            do {
                out.println("Please Login");
                out.println("Username: ");
                userIn = in.readLine();
                out.println("Password: ");
                passIn = in.readLine();
            } while(!authUser(userIn, passIn));
            out.println("Login Successful");

            send(Server.roomList() + COMMANDS);
            while(true) {
                String messageIn = in.readLine();
                parseInput(messageIn);
            }
        } catch(Exception e) {
            room.sendServerMsg(user.getName() + " disconnected.");
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
            secret = ka.generateSecret();
            System.out.println("Session key generated.");
            System.out.println(Base64.getEncoder().encodeToString(secret));

        } catch(Exception e) {
            System.out.println(e);
        }
    }

    public void setAlgo(int algo) throws Exception {
        switch(algo) {
            case 1:
                DESKeySpec desKeySpec = new DESKeySpec( secret ); //@#$#@*
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
                SecretKey key = keyFactory.generateSecret(desKeySpec);
                break;
            case 2:
                break;
        }

        System.out.println("Algorithm set");
    }

    public Boolean authUser(String name, String pass) throws Exception {
        System.out.println(name);
        System.out.println(pass);
        ArrayList<User> users = Server.getUsers();
        for(int i = 0; i < users.size(); i++) {
            if (users.get(i).validLogin(name, pass))
                return true;
        }
        return false;
    }

    public void parseInput(String input) {
        if(input.charAt(0) == '/') {
            String[] subStr = input.split(" ", 2);
            switch(subStr[0]) {
                case "/join":
                    try {
                        if(room != null) {
                            room.removeClient(this);
                        } 
                        room = Server.getRoom(Integer.parseInt(subStr[1]));
                        room.addClient(this);
                        send("Joined " + room.getName());
                    } catch(IndexOutOfBoundsException e) {
                        send("Invalid room number");
                    }
                    break;
                case "/create":
                    try {
                        if(room != null) {
                            room.removeClient(this);
                        }
                        room = new Room(subStr[1]);
                        Server.addRoom(room);
                        room.addClient(this);
                        send("Joined " + room.getName());
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
    
    public User getUser() {
        return user;
    }
}
