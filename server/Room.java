import java.util.ArrayList;

public class Room {
    private String name;
    private ArrayList<ServerThread> clients = new ArrayList<>();

    public Room(String name) {
        this.name = name;
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

    public String getRoomName() {
        return name;
    }

    public void addClient(ServerThread client) {
        sendToAll(client.getUser().getName() + " joined the room.");
        clients.add(client);
    }

    public void removeClient(ServerThread client) {
        clients.remove(client);
        sendToAll(client.getUser().getName() + " left the room.");
        if(clients.size() == 0) {
            Server.removeRoom(this);
        }
    }
}
