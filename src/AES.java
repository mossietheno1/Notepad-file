import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.Base64;
public class AES {
public static String encrypt(Cipher c, Key k, String data) throws
Exception {
c.init(Cipher.ENCRYPT_MODE, k);
byte[] encryptedData = c.doFinal(data.getBytes());
String encodedData = Base64.getEncoder().encodeToString(encryptedData)
;
return encodedData;
}
public static String decrypt(Cipher c, Key k, String data) throws
Exception {
c.init(Cipher.DECRYPT_MODE, k);
byte[] decodedData = Base64.getDecoder().decode(data);
byte[] decryptedData = c.doFinal(decodedData);
return new String(decryptedData);
}
public static void main(String[] args) throws Exception {
Security.addProvider(new BouncyCastleProvider());
String key = "thebestsecretkey";
String plaintext = "Hello world!";
//System.out.println("Key: " + key);
//System.out.println("Plaintext: " + plaintext);
Cipher c = Cipher.getInstance("AES", "BC");
Key k = new SecretKeySpec(key.getBytes(), "AES");
String ciphertext = encrypt(c, k, plaintext);
//System.out.println("Ciphertext: " + ciphertext);
String plaintext2 = decrypt(c, k, ciphertext);
//System.out.println("Plaintext (decrypted): " + plaintext2);
}
}