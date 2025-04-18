package com.google.apigee.callouts;
import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.jce.spec.IESParameterSpec;
/**
 * EccCrypto is the entry point for encryption and decryption operations.
 * It uses EccEncryption and EccDecryption classes to handle ECIES-based operations.
 * 
 * Writer: Rajesh K.
 */
public class ECCUtil implements Execution {

    private final Map<String, String> properties;
    private static final Pattern variableReferencePattern = Pattern.compile("(.*?)\\{([^\\{\\} ]+?)\\}(.*?)");

    /**
     * Constructor to initialize properties and generate shared IESParameterSpec parameters.
     */
    public ECCUtil(Map<String, String> properties) {
        this.properties = properties;
    }

    @Override
    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            // Retrieve necessary properties
            String action = this.properties.getOrDefault("action", "encrypt");
            String inputMessage = getSimpleRequiredProperty("inputMessage", messageContext);
            String publicKeyProperty = getSimpleRequiredProperty("publicKey", messageContext);
            String privateKeyProperty = getSimpleRequiredProperty("privateKey", messageContext);

            // Validation for mandatory inputs
            if (inputMessage == null || inputMessage.trim().isEmpty()) {
                throw new IllegalArgumentException("Invalid inputMessage: Blank Values");
            } else if (publicKeyProperty == null || publicKeyProperty.trim().isEmpty()) {
                throw new IllegalArgumentException("Invalid publicKeyProperty: Blank Values");
            } else if (privateKeyProperty == null || privateKeyProperty.trim().isEmpty()) {
                throw new IllegalArgumentException("Invalid privateKeyProperty: Blank Values");
            } else if (action == null || action.trim().isEmpty()) {
                throw new IllegalArgumentException("Invalid action: Blank Values");
            }
            // Perform encryption or decryption based on action
            if ("encrypt".equalsIgnoreCase(action)) {
                EccEncryption encryption = new EccEncryption();
                encryption.setPublicKey(publicKeyProperty);
                String encryptedData = encryption.encrypt(inputMessage);
                messageContext.setVariable("encryptedResponse", encryptedData);
            } else if ("decrypt".equalsIgnoreCase(action)) {
                EccDecryption decryption = new EccDecryption();
                decryption.setPrivateKey(privateKeyProperty);
                String decryptedData = decryption.decrypt(inputMessage);
                messageContext.setVariable("decryptedResponse", decryptedData);
            } else {
                throw new IllegalArgumentException("Invalid action: " + action + ". Use 'encrypt' or 'decrypt'.");
            }

            return ExecutionResult.SUCCESS;

        } catch (Exception e) {
            messageContext.setVariable("ecc.error", e.getMessage());
            e.printStackTrace();
            return ExecutionResult.ABORT;
        }
    }

    // Helper method to retrieve a required property and resolve its value
    private String getSimpleRequiredProperty(String propName, MessageContext msgCtxt) {
        String value = this.properties.get(propName);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(propName + " resolves to an empty string");
        }
        return resolvePropertyValue(value.trim(), msgCtxt);
    }

    // Resolves variable references (e.g., {variableName}) in the property value
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        Matcher matcher = variableReferencePattern.matcher(spec);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(sb, "");
            sb.append(matcher.group(1));
            Object v = msgCtxt.getVariable(matcher.group(2));
            if (v != null) {
                sb.append(v.toString());
            }
            sb.append(matcher.group(3));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }
}
