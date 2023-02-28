import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class P {

    private static final String SECRET_KEY = "123456789";
    private static final String SALT = "123456";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final String HASHING_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = (int) Math.pow(2, 16);

    private static final byte[] DEFAULT_IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private static final IvParameterSpec IV_PARAMETER_SPEC = new IvParameterSpec(DEFAULT_IV);

    public static String encrypt(String plaintext) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASHING_ALGORITHM);
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV_PARAMETER_SPEC);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException |
                 InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error occurred during encryption: " + e);
        }
        return null;
    }

    public static String decrypt(String ciphertext) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASHING_ALGORITHM);
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IV_PARAMETER_SPEC);
            return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException |
                 InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error occurred during decryption: " + e);
        }
        return null;
    }

    public static void main(String[] args) {
        String plainText = "AES Encryption";
        String cipherText = encrypt(plainText);
        String decryptedText = decrypt(cipherText);
        System.out.println("Original value: " + plainText);
        System.out.println("Encrypted value: " + cipherText);
        System.out.println("Decrypted value: " + decryptedText);
    }
}
