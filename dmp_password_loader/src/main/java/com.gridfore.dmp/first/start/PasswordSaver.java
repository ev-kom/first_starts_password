package com.gridfore.dmp.first.start;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Output;
import org.objenesis.strategy.StdInstantiatorStrategy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class PasswordSaver {
    private static final int BUFFER_SIZE = 64 * 1024 * 1024; // 64 MB
    private static final HashMap<String, byte[]> passwordMap = new HashMap<>();

    private static List<String> tokensList;
    private static String pathToDb;
    private static String cacheName;
    private static String algorithm;
    private static String userPublicKeyPath;
    private static String servicePublicKeyPath;
    private static PublicKey userPublicKey;
    private static PublicKey servicePublicKey;

    private static final ThreadLocal<Kryo> kryoThreadLocal = ThreadLocal.withInitial(() -> {
        Kryo kryo = new Kryo();
        kryo.setInstantiatorStrategy(new Kryo.DefaultInstantiatorStrategy(
                new StdInstantiatorStrategy()
        ));
        return kryo;
    });

    public static void main(String[] args) {

        Properties props = getProperties();
        loadProperties(props);
        userPublicKey = loadPublicKey(userPublicKeyPath);
        servicePublicKey = loadPublicKey(servicePublicKeyPath);

        Scanner scanner = new Scanner(System.in);
        tokensList.forEach(token -> {
            System.out.println("Enter the password for token [" + token + "]: ");
            String password = scanner.next();
            byte[] userEncryptData = encryptData(password.getBytes(), userPublicKey);
            passwordMap.put(token, encryptData(userEncryptData, servicePublicKey));
        });
        scanner.close();

        flush();
    }

    public static byte[] encryptData(byte[] data, PublicKey key) {
        try {
            Cipher cipherEncrypt = Cipher.getInstance(algorithm);
            cipherEncrypt.init(Cipher.ENCRYPT_MODE, key);
            return cipherEncrypt.doFinal(data);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error during data encrypting " + algorithm, e);
        }
    }

    public static PublicKey loadPublicKey(String path) {
        KeyFactory keyFactory = getKeyFactory();
        try {
            return keyFactory.generatePublic(new X509EncodedKeySpec(getKeyBytes(path)));
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Error encoding public key " + path, e);
        }
    }

    public static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Error creating key factory for algorithm " + algorithm, e);
        }
    }

    public static byte[] getKeyBytes(String path) {
        Path file = Paths.get(path);
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new IllegalArgumentException("Error reading public key file " + path, e);
        }
    }

    public static Properties getProperties() {
        Properties properties = new Properties();
        try {
            File jarPath = new File(PasswordSaver.class.getProtectionDomain().getCodeSource().getLocation().getPath());
            String propertiesPath = jarPath.getParentFile().getAbsolutePath();
            System.out.println("Properties path: " + propertiesPath);
            properties.load(new FileInputStream(propertiesPath+"/initial.properties"));
            return properties;
        } catch (IOException e) {
            throw new IllegalArgumentException("Error loading properties ", e);
        }
    }

    public static void flush() {
        try (FileOutputStream outputStream = new FileOutputStream(getPersistentFileName())) {
            outputStream.getChannel().truncate(0);

            Kryo kryo = kryoThreadLocal.get();

            Output output = new Output(outputStream, BUFFER_SIZE);

            passwordMap.forEach((key, value) -> {
                kryo.writeClassAndObject(output, key);
                kryo.writeClassAndObject(output, value);
            });

            output.flush();
        } catch (IOException e) {
            throw new IllegalStateException("Can't save data to persistent storage ", e);
        }
    }

    public static String getPersistentFileName() {
        return pathToDb + File.separator + cacheName + ".bin";
    }

    public static void loadProperties(Properties props) {
        tokensList = Arrays.asList(props.getProperty("initial.tokens.list").split("\\s*,\\s*"));
        pathToDb = props.getProperty("initial.path.to.db");
        cacheName = props.getProperty("initial.cache.name");
        algorithm = props.getProperty("initial.algorithm");
        userPublicKeyPath = props.getProperty("initial.user.public.key.path");
        servicePublicKeyPath = props.getProperty("initial.service.public.key.path");

        try {
            Files.createDirectories(Paths.get(pathToDb));
        } catch (IOException e) {
            throw new IllegalArgumentException("Can't create directory " + pathToDb, e);
        }
    }

}
