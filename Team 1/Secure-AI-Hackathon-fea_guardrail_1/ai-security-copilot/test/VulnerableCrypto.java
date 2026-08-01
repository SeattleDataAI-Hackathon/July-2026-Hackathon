import java.security.MessageDigest;

public class VulnerableCrypto {

    public static void main(String[] args) throws Exception {

        MessageDigest digest =
            MessageDigest.getInstance("SHA1");

        byte[] hash =
            digest.digest("sensitive-data".getBytes());

        System.out.println(hash);
    }
}