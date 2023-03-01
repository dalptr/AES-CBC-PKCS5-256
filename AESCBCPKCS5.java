import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;

public class AESCBCPKCS5 {
    public boolean stableOperation;
    int keyLength;
    private final String TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private final byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private final IvParameterSpec IV_PARAMETER_SPEC = new IvParameterSpec(IV);
    SecretKeyFactory factory;
    SecretKey aesSecretKey;
    SecretKeySpec secretKeySpec;

    AESCBCPKCS5(String secretKey, String salt, int keyLength) {
        try {
            this.keyLength = (keyLength == 128 || keyLength == 192 || keyLength == 256 ? keyLength : 256);
            int ITERATION_COUNT = (int) Math.pow(2, 16);
            KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, keyLength);
            String HASHING_ALGORITHM = "PBKDF2WithHmacSHA256";
            factory = SecretKeyFactory.getInstance(HASHING_ALGORITHM);
            aesSecretKey = factory.generateSecret(keySpec);
            secretKeySpec = new SecretKeySpec(aesSecretKey.getEncoded(), "AES");
        }
        catch (Exception e){
            stableOperation = false;
            return;
        }
        stableOperation = testOperation();

    }
    public boolean testOperation(){
        String text = "ABC";
        return Objects.equals(decrypt(encrypt(text)), text);
    }

    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, IV_PARAMETER_SPEC);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException |
                 BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error occurred during encryption: " + e);
        }
        return null;
    }

    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, IV_PARAMETER_SPEC);
            return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException |
                 BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error occurred during decryption: " + e);
        }
        return null;
    }
}
