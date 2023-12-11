import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESRSAEncryptionScheme {
    private SecretKey aesSecretKey;
    private PublicKey rsaPublicKey;

    private static final String AES_ALGORITHM_NAME = "AES";
    public static final String NEW_LINE_CHARACTER = "\n";
    public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
    public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
    public static final String EMPTY_STRING = "";
    public static final String RSA_ALGORITHM = "RSA";
    private static final String FACTORY_INSTANCE = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5PADDING";
    private static final String SECRET_KEY_TYPE = "AES";
    private static final byte[] IV_CODE = new byte[16];
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;
    private static final int AES_KEY_SIZE = 128;
    private static final String SALT = "rsaaes@1234salt";
    private static final int CIPHER_MODE = Cipher.ENCRYPT_MODE;

    public void createAESKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM_NAME);
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        this.setAesSecretKey(key);
    }

    public void readRSAKeys(String publicKeyFilePath) {
        try {
            File keyFile = new File(publicKeyFilePath);
            if (!keyFile.exists()) {
                throw new IOException("Public key file not found: " + publicKeyFilePath);
            }
            byte[] publicKey = Files.readAllBytes(keyFile.toPath());

            String keyString = new String(publicKey);
            keyString = keyString.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
                    .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
                    .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING);

            publicKey = keyString.getBytes();
            Key generatePublic = KeyFactory.getInstance(
                    RSA_ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));

            this.setRsaPublicKey(generatePublic);
        } catch (NoSuchAlgorithmException e) {

            System.err.println(
                    "[AESRSAEncryptionScheme.readRSAKeys]: Encryption algorithm not found: " + e.getMessage());
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("[AESRSAEncryptionScheme.readRSAKeys]:Invalid encryption key: " + e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void encryptionUsingRSA(SecretKey aesKey, String fileNameWithoutExtension, String extension) {
        try {

            Cipher cipherInstance = Cipher.getInstance(RSA_ALGORITHM);
            cipherInstance.init(Cipher.ENCRYPT_MODE, this.getRsaPublicKey());

            byte[] encryptedByteArray = cipherInstance
                    .doFinal(Base64.getEncoder().encodeToString(aesKey.getEncoded()).getBytes());

            FileWriter fileWriter = new FileWriter(fileNameWithoutExtension + "_Encrypted_AES.txt");
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            bufferedWriter.write(Base64.getEncoder().encodeToString(encryptedByteArray));
            bufferedWriter.close();

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Encryption algorithm not found: " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            System.err.println("Padding scheme not available: " + e.getMessage());
        } catch (InvalidKeyException e) {
            System.err.println("Invalid encryption key: " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            System.err.println("Invalid block size: " + e.getMessage());
        } catch (BadPaddingException e) {
            System.err.println("Invalid padding: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static byte[] addIVToCipher(byte[] cipherText) {

        byte[] cipherWithIv = new byte[IV_CODE.length + cipherText.length];
        System.arraycopy(IV_CODE, 0, cipherWithIv, 0, IV_CODE.length);
        System.arraycopy(cipherText, 0, cipherWithIv, IV_CODE.length, cipherText.length);
        return cipherWithIv;
    }

    private static Cipher initCipher(String secretKey, String salt, int mode) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_INSTANCE);
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
        SecretKeySpec sKeySpec = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_KEY_TYPE);
        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);

        // Generating random IV
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV_CODE);
        cipher.init(mode, sKeySpec, new IvParameterSpec(IV_CODE));
        return cipher;
    }

    public void aes_encryption_for_files(SecretKey key,
            File inputFile, File outputFile) throws Exception {

        byte[] encodedKey = key.getEncoded();
        String encodedKeyString = Base64.getEncoder().encodeToString(encodedKey);

        Cipher cipher = null;
        try {
            cipher = initCipher(encodedKeyString, SALT, CIPHER_MODE);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        byte[] fileBytes = Files.readAllBytes(inputFile.toPath());

        byte[] cipherText = null;
        try {
            cipherText = cipher.doFinal(fileBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        byte[] cipherWithIv = addIVToCipher(cipherText);

        FileWriter fileWriter = new FileWriter(outputFile);
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
        try {
            bufferedWriter.write(Base64.getEncoder().encodeToString(cipherWithIv));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            bufferedWriter.close();
        }
    }

    public void encrypt(String orignalFilePath, String publicKeyFilePath) {

        try {
            createAESKey(AES_KEY_SIZE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // Reading the original csv which needs to go through AES Encryption
        File original_file = Paths.get(
                orignalFilePath)
                .toFile();

        String fileNameWithExtension = original_file.toString();

        String fileNameWithoutExtension = "";
        String extension = "";
        int index = fileNameWithExtension.lastIndexOf('.');
        if (index > 0) {
            extension = fileNameWithExtension.substring(index + 1);
            fileNameWithoutExtension = fileNameWithExtension.substring(0, fileNameWithExtension.lastIndexOf("."));
        }

        File encrypted_file = new File(fileNameWithoutExtension + "_Encrypted" + "." + extension);

        // Storing the AES Key in the file named "AES_Key.txt"
        byte[] rawData = getAesSecretKey().getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(rawData);

        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // Performing the AES Encryption on the original file
        try {
            aes_encryption_for_files(
                    originalKey, original_file,
                    encrypted_file);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Reading the RSA public key in files
        readRSAKeys(publicKeyFilePath);

        // Encrypting the AES Secret Key using the RSA public key
        encryptionUsingRSA(originalKey, fileNameWithoutExtension, extension);

    }

    public SecretKey getAesSecretKey() {
        return aesSecretKey;
    }

    public void setAesSecretKey(SecretKey aesSecretKey) {
        this.aesSecretKey = aesSecretKey;
    }

    public PublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    public void setRsaPublicKey(Key generatePublic) {
        this.rsaPublicKey = (PublicKey) generatePublic;
    }
}
