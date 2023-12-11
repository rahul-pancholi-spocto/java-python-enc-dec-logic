
public class EncryptionMain {

    public static void main(String[] args) throws Exception {
        final String ORIGNAL_FILE_PATH = "test_uat.csv";
        final String PUBLIC_KEY_FILE_PATH = "public_key.pem";
        AESRSAEncryptionScheme aes_rsa_encryption = new AESRSAEncryptionScheme();
        aes_rsa_encryption.encrypt(ORIGNAL_FILE_PATH, PUBLIC_KEY_FILE_PATH);
    }
}
