package com.google.apigee.callouts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
/**
 * EccCrypto is the entry point for encryption and decryption operations.
 * It uses EccEncryption classes to handle ECIES-based operations.
 * 
 * Writer: Rajesh K.
 */
public class ECCEncryption {

    // Declare a public key field to store the EC public key
    private PublicKey publicKey;

    // Static block to add BouncyCastle as a security provider for cryptographic operations
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Default constructor
    public ECCEncryption() {}

    // Method to set the public key using a Base64-encoded string
    public void setPublicKey(String base64PublicKey) throws Exception {
        try {
            // Decode the Base64-encoded public key string into a byte array
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
            
            // Create a key specification from the byte array
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            
            // Get a KeyFactory for EC (Elliptic Curve) and BouncyCastle as the provider
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            
            // Generate the PublicKey from the key specification
            this.publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            // If there is an error in setting the public key, throw an exception with a detailed message
            throw new Exception("Failed to set public key. Ensure it is valid and Base64-encoded. Error: " + e.getMessage(), e);
        }
    }

    // Method to encrypt an input message using the ECIES algorithm and the provided IES parameters
    public String encrypt(String inputMessage) throws Exception {
        // Ensure that the public key has been set before encryption
        if (publicKey == null) {
            throw new Exception("Public key is not initialized.");
        }

        try {
            // Initialize a Cipher instance for ECIES (Elliptic Curve Integrated Encryption Scheme)
            Cipher cipher = Cipher.getInstance("ECIES", new BouncyCastleProvider());
            
            // Set up the cipher in encryption mode with the public key and IES parameters
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Perform the encryption on the input message (convert to bytes using UTF-8 encoding)
            byte[] encryptedBytes = cipher.doFinal(inputMessage.getBytes("UTF-8"));
            
            // Return the encrypted message as a Base64-encoded string
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            // If encryption fails, throw an exception with a detailed error message
            throw new Exception("Encryption failed. Error: " + e.getMessage(), e);
        }
    }
}
