**Apigee ECC Encryption & Decryption – Custom Java Callout**

This repository contains custom Java code for ECC (Elliptic Curve Cryptography) encryption and decryption, designed to be used as a Java callout in Apigee Edge or Apigee X.

🔐 Overview
ECC provides a modern, lightweight encryption method ideal for high-security and performance-sensitive applications. This Java callout enables Apigee proxies to handle encrypted payloads using ECC for both inbound and outbound communication.

📦 Features
ECC Key Pair generation

ECC-based encryption and decryption of text payloads

Customizable key storage and retrieval

Seamless integration with Apigee via Java callout

Uses java.security and javax.crypto for cryptographic operations

📁 Project Structure
Apigee-CustomPolicy-EccCrypton

├── src/

│   └── com/apigee/ecc/

│       ├── ECCEncryptCallout.java

│       ├── ECCDecryptCallout.java

│       └── ECCUtil.java

├── pom.xml

└── README.md

🚀 Getting Started
Prerequisites
Java 8 or higher

Maven

Apigee Edge or Apigee X environment with Java callout support

Build
Use Maven to build the JAR:

bash
Copy
Edit
mvn clean install
The compiled .jar will be located in the target/ directory.

Deploy to Apigee
Upload the JAR to your Apigee environment under the API proxy's resources/java/ directory.

Add a Java callout policy in your proxy like this:

xml
Copy
Edit
<JavaCallout name="ECC-Encrypt-Callout">
    <ClassName>com.apigee.ecc.ECCEncryptCallout</ClassName>
    <ResourceURL>java://ecc-encryption.jar</ResourceURL>
    <Properties>
        <Property name="input">request.content</Property>
        <Property name="output">encrypted.payload</Property>
    </Properties>
</JavaCallout>
Use the encrypted.payload or decrypted.payload in your API logic accordingly.

🔧 Configuration Options
Property	Description
input	Flow variable containing the input payload
output	Variable to store the output result
key.alias	(Optional) Alias for key pair retrieval
🛡️ Security
Ensure private keys are stored securely. The utility includes options for in-memory and external key management.

This implementation is for educational and proof-of-concept use. For production, implement secure key management practices (e.g., KMS, HSM).

📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

✨ Author
Rajesh K.
For questions, suggestions, or contributions, feel free to open an issue or pull request.

# Apigee-CustomPolicy-EccCrypto
Custom Java callout for Apigee Edge/X to perform ECC (Elliptic Curve Cryptography) based encryption and decryption of API payloads. Lightweight, secure, and integration-ready.
