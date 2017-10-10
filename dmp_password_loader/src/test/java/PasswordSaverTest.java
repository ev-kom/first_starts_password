import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.sun.istack.internal.NotNull;
import org.junit.Test;
import org.objenesis.strategy.StdInstantiatorStrategy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;

public class PasswordSaverTest {

    private static final int BUFFER_SIZE = 64 * 1024 * 1024; // 64 MB
    private static final HashMap<String, byte[]> passwordMap = new HashMap<>();

    private static String pathToDb;
    private static String cacheName;
    private static String algorithm;

    private static final ThreadLocal<Kryo> kryoThreadLocal = ThreadLocal.withInitial(() -> {
        Kryo kryo = new Kryo();
        kryo.setInstantiatorStrategy(new Kryo.DefaultInstantiatorStrategy(
                new StdInstantiatorStrategy()
        ));
        return kryo;
    });

    @Test
    public void passwordTest() {
        Properties props = getProperties();
        loadProperties(props);

        PrivateKey privateKey = loadPrivateKey("security/private.key");

        loadAll();

        passwordMap.forEach((key, value) ->{
            System.out.println("Token: " + key + ", Encrypted password: " + new String(value));
            byte[] decryptPassword = decryptData(value, privateKey);
            System.out.println("Token: " + key + ", Decrypted password: " + new String(decryptPassword));
        });

    }

    public static void loadAll() {
        try (FileInputStream inputStream = new FileInputStream(getPersistentFileName())) {
            Kryo kryo = kryoThreadLocal.get();

            Input input = new Input(inputStream, BUFFER_SIZE);

            while (input.available() > 0) {
                String key = (String) kryo.readClassAndObject(input);
                byte[] value = (byte[]) kryo.readClassAndObject(input);

                passwordMap.put(key, value);
            }

        } catch (FileNotFoundException e) {
            System.out.println("Can't load cache from file {} cause it doesn't exist (yet)" + getPersistentFileName());
        } catch (IOException e) {
            throw new IllegalArgumentException("can't load data from persistent storage " + algorithm, e);
        }
    }

    private static String getPersistentFileName() {
        return pathToDb + File.separator + cacheName + ".bin";
    }

    public static void loadProperties(Properties props) {
        pathToDb = props.getProperty("initial.path.to.db");
        cacheName = props.getProperty("initial.cache.name");
        algorithm = props.getProperty("initial.algorithm");

        try {
            Files.createDirectories(Paths.get(pathToDb));
        } catch (IOException e) {
            throw new IllegalArgumentException("Can't create directory " + pathToDb, e);
        }
    }

    @NotNull
    public static Properties getProperties() {
        Properties properties = new Properties();
        InputStream input;
        try {
            String name = Paths.get(PasswordSaverTest.class.getResource("/initial.properties").toURI()).toString();
            input = new FileInputStream(name);
            properties.load(input);
            return properties;
        } catch (IOException | URISyntaxException e) {
            throw new IllegalArgumentException("Error loading properties ", e);
        }
    }

    public static PrivateKey loadPrivateKey(String path) {
        KeyFactory keyFactory = getKeyFactory();
        try {
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(getKeyBytes(path)));
        } catch (InvalidKeySpecException | IOException e) {
            throw new IllegalStateException("Error encoding private key " + path, e);
        }
    }

    public static byte[] getKeyBytes(String path) throws IOException {
        Path file = Paths.get(path);
        return Files.readAllBytes(file);
    }

    public static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Error creating key factory for algorithm " + algorithm, e);
        }
    }

    public static byte[] decryptData(byte[] data, PrivateKey key) {
        try {
            Cipher cipherDecrypt = Cipher.getInstance(algorithm);
            cipherDecrypt.init(Cipher.DECRYPT_MODE, key);
            return cipherDecrypt.doFinal(data);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error during data encrypting " + algorithm, e);
        }
    }

}
