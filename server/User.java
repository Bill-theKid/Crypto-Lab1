import java.security.*;

public class User {

    private String username;
    private String passwordHash;

    public void setName(String username) {
        this.username = username;
    }

    public String getName() {
        return username;
    }

    public void setPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        passwordHash = hash.toString();
    }

    public Boolean passwordMatches(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        return passwordHash.equals(hash.toString());
    }

    public Boolean validLogin(String name, String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        return (passwordHash.equals(hash.toString()) &&
                username.equals(name));
    }
}
