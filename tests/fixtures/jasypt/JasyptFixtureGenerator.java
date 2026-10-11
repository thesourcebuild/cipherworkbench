import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.IvGenerator;
import org.jasypt.salt.SaltGenerator;

/** Regenerates the committed Jasypt 1.9.3 / SunJCE interoperability fixtures. */
public final class JasyptFixtureGenerator {
    private static final class IncludedSalt implements SaltGenerator {
        private final byte[] value;

        IncludedSalt(String hex) { this.value = fromHex(hex); }

        public byte[] generateSalt(int length) {
            if (length != value.length) throw new IllegalArgumentException("salt length");
            return value.clone();
        }

        public boolean includePlainSaltInEncryptionResults() { return true; }
    }

    private static final class IncludedIv implements IvGenerator {
        private final byte[] value;

        IncludedIv(String hex) { this.value = fromHex(hex); }

        public byte[] generateIv(int length) {
            if (length != value.length) throw new IllegalArgumentException("IV length");
            return value.clone();
        }

        public boolean includePlainIvInEncryptionResults() { return true; }
    }

    private static byte[] fromHex(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static StandardPBEStringEncryptor encryptor(
            String algorithm, String password, int iterations, String salt, String iv, String format) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm(algorithm);
        encryptor.setPassword(password);
        encryptor.setKeyObtentionIterations(iterations);
        encryptor.setSaltGenerator(new IncludedSalt(salt));
        if (!iv.isEmpty()) encryptor.setIvGenerator(new IncludedIv(iv));
        encryptor.setStringOutputType(format);
        return encryptor;
    }

    private static void vector(
            String id, String algorithm, String password, int iterations,
            String salt, String iv, String plaintext) {
        StandardPBEStringEncryptor base64 = encryptor(
                algorithm, password, iterations, salt, iv, "base64");
        StandardPBEStringEncryptor hex = encryptor(
                algorithm, password, iterations, salt, iv, "hexadecimal");
        String base64Ciphertext = base64.encrypt(plaintext);
        String hexCiphertext = hex.encrypt(plaintext);
        byte[] corrupted = Base64.getDecoder().decode(base64Ciphertext);
        corrupted[corrupted.length - 1] ^= 1;
        String corruptedBase64 = Base64.getEncoder().encodeToString(corrupted);
        boolean wrongPasswordFails;
        boolean corruptionFails;
        try {
            encryptor(algorithm, "wrong-password", iterations, salt, iv, "base64")
                    .decrypt(base64Ciphertext);
            wrongPasswordFails = false;
        } catch (RuntimeException expected) {
            wrongPasswordFails = true;
        }
        try {
            base64.decrypt(corruptedBase64);
            corruptionFails = false;
        } catch (RuntimeException expected) {
            corruptionFails = true;
        }
        System.out.printf(
                "%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%s%n",
                id, algorithm, password, iterations, salt, iv,
                Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8)),
                base64Ciphertext, hexCiphertext, corruptedBase64,
                wrongPasswordFails + "," + corruptionFails);
        System.out.println("decrypt-base64=" + base64.decrypt(base64Ciphertext));
        System.out.println("decrypt-hex=" + hex.decrypt(hexCiphertext));
    }

    public static void main(String[] args) {
        vector("legacy", "PBEWithMD5AndDES", "fixture-password", 1000,
                "0001020304050607", "", "Jasypt interop fixture");
        vector("aes", "PBEWITHHMACSHA512ANDAES_256", "fixture-password", 1000,
                "000102030405060708090a0b0c0d0e0f", "f0e0d0c0b0a090807060504030201000",
                "Jasypt interop fixture");
        vector("unicode-plaintext", "PBEWITHHMACSHA512ANDAES_256", "unicode-password", 4096,
                "101112131415161718191a1b1c1d1e1f", "202122232425262728292a2b2c2d2e2f",
                "Zażółć gęślą jaźń 🔐");

        try {
            encryptor("PBEWITHHMACSHA512ANDAES_256", "pässword", 1000,
                    "000102030405060708090a0b0c0d0e0f", "f0e0d0c0b0a090807060504030201000", "base64")
                    .encrypt("never encrypted");
            System.out.println("unicode-password=accepted");
        } catch (RuntimeException expected) {
            System.out.println("unicode-password=rejected:" + expected.getClass().getSimpleName());
        }
    }
}
