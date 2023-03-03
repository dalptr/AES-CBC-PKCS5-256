import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;

public class AESCBCPKCS5 {
    public boolean stableOperation;
    public static final String salt = "9564645546664646464646";
    public static final int keyLength = 256;
    private static final String TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private static final IvParameterSpec IV_PARAMETER_SPEC = new IvParameterSpec(IV);
    private static final int ITERATION_COUNT = (int) Math.pow(2, 16);
    SecretKeyFactory factory;
    SecretKey aesSecretKey;
    SecretKeySpec secretKeySpec;

    AESCBCPKCS5(String secretKey) {
        try {
            KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, keyLength);
            String HASHING_ALGORITHM = "PBKDF2WithHmacSHA256";
            factory = SecretKeyFactory.getInstance(HASHING_ALGORITHM);
            aesSecretKey = factory.generateSecret(keySpec);
            secretKeySpec = new SecretKeySpec(aesSecretKey.getEncoded(), "AES");
        } catch (Exception e) {
            stableOperation = false;
            return;
        }
        stableOperation = testOperation();
    }

    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, IV_PARAMETER_SPEC);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ignored) {
        }
        return null;
    }

    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, IV_PARAMETER_SPEC);
            return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
        } catch (Exception ignored) {
            return null;
        }
    }

    public boolean testOperation() {
        String plaintext = "ABC";
        String ciphertext = encrypt(plaintext);
        String text = decrypt(ciphertext);
        return Objects.equals(plaintext, text);
    }
}
