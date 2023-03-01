import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
// Simple Key Management for Internet Protocols with Diffie-Hellman
// To be used with SkipServer2.  The contents of the encrypted file
// transmitted by the server is received in blocks, decryped and printed
// on the CRT and to a local file.

// Usage java SkipClient2 ipAddressOfServer port fileToHoldDecryptedPlainText

public class SkipClient2 {
    public static void main(String[] args) throws Exception {
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String outfile = args[2];

        // Create a Diffie-Hellman key pair (public and private).
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(Skip.sDHParameterSpec);
        KeyPair LukekeyPair = kpg.genKeyPair();

        // Create socket and contact host.
        Socket s = new Socket(host, port); // Wait to be recognized.

        DataInputStream myin = new DataInputStream(s.getInputStream());
        DataOutputStream myout = new DataOutputStream(s.getOutputStream());

        // Send our public key to host.
        byte[] keyBytes = LukekeyPair.getPublic().getEncoded();
        myout.writeInt(keyBytes.length);
        myout.write(keyBytes);

        // Accept public key from host (length, key in bytes).
        keyBytes = new byte[myin.readInt()];
        myin.readFully(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
        PublicKey HanPublicKey = kf.generatePublic(x509Spec);

        // Generate the secret session key.
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(LukekeyPair.getPrivate());
        ka.doPhase(HanPublicKey, true);
        byte[] secret = ka.generateSecret();

        // in c:\jdk1.2.2\jre\classes\edu.shsu.util.BASE64
        // System.out.println( edu.shsu.util.BASE64.encode(secret) );

        FileOutputStream fout = new FileOutputStream(outfile);

        // First create a key specification from the password, then the key.
        DESKeySpec desKeySpec = new DESKeySpec(secret); // @#$#@*
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey desKey = keyFactory.generateSecret(desKeySpec);

        // Read the initialization vector.
        int ivSize = myin.readInt();
        byte[] iv = new byte[ivSize];
        myin.readFully(iv);
        IvParameterSpec ivps = new IvParameterSpec(iv);

        // use Data Encryption Standard
        Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
        des.init(Cipher.DECRYPT_MODE, desKey, ivps);

        // Accept the encryped transmission, decrypt, and save in file.
        byte[] input = new byte[64];
        while (true) {
            int bytesRead = myin.read(input);
            if (bytesRead == -1)
                break;
            byte[] output = des.update(input, 0, bytesRead);
            if (output != null) {
                fout.write(output);
                System.out.print(new String(output));
            }
        }

        byte[] output = des.doFinal();
        if (output != null) {
            fout.write(output);
            System.out.print(new String(output));
        }

        fout.flush();
        fout.close();
        myout.close();
        myin.close();
    }
}
