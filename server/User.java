import java.security.*;
import java.util.Arrays;

public class User {

    private String username;
    private byte[] passwordHash;

    public User() {
        username = null;
        passwordHash = null;
    }

    public void setName(String username) {
        this.username = username;
    }

    public String getName() {
        return username;
    }

    public void setPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            passwordHash = hash;
        } catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public Boolean validLogin(String name, String password) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());

            return (Arrays.equals(hash, passwordHash) &&
                username.equals(name));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    public String toString() {
        return "username: " + username + " - password: " + passwordHash;
    }
}
