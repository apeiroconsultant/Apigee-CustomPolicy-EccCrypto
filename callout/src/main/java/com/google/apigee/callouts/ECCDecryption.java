package com.google.apigee.callouts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
/**
 * EccCrypto is the entry point for encryption and decryption operations.
 * It uses EccEncryption classes to handle ECIES-based operations.
 * 
 * Writer: Rajesh K.
 */
public class ECCDecryption {

    // Declare a private key field to store the EC private key
    private PrivateKey privateKey;

    // Static block to add BouncyCastle as a security provider for cryptographic operations
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Default constructor
    public ECCDecryption() {}

    // Method to set the private key using a Base64-encoded string
    public void setPrivateKey(String base64PrivateKey) throws Exception {
        try {
            // Decode the Base64-encoded private key string into a byte array
            byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);
            
            // Create a key specification from the byte array
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            
            // Get a KeyFactory for EC (Elliptic Curve) and BouncyCastle as the provider
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            
            // Generate the PrivateKey from the key specification
            this.privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            // If there is an error in setting the private key, throw an exception with a detailed message
            throw new Exception("Failed to set private key. Ensure it is valid and Base64-encoded. Error: " + e.getMessage(), e);
        }
    }

    // Method to decrypt an encrypted message using the ECIES algorithm and the provided IES parameters
    public String decrypt(String encryptedInput) throws Exception {
        // Ensure that the private key has been set before decryption
        if (privateKey == null) {
            throw new Exception("Private key is not initialized.");
        }

        try {
            // Initialize a Cipher instance for ECIES (Elliptic Curve Integrated Encryption Scheme)
            Cipher cipher = Cipher.getInstance("ECIES", new BouncyCastleProvider());
            
            // Set up the cipher in decryption mode with the private key and IES parameters
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Perform the decryption on the encrypted input (first decode the Base64 string to bytes)
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedInput));
            
            // Return the decrypted message as a UTF-8 string
            return new String(decryptedBytes, "UTF-8");

        } catch (Exception e) {
            // If decryption fails, throw an exception with a detailed error message
            throw new Exception("Decryption failed. Error: " + e.getMessage(), e);
        }
    }
}
