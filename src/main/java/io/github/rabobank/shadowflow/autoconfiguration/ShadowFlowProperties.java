package io.github.rabobank.shadowflow.autoconfiguration;

import jakarta.validation.constraints.Max;import jakarta.validation.constraints.NotBlank;import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.PositiveOrZero;import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RefreshScope
@ConfigurationProperties("shadowflow")
public class ShadowFlowProperties {
    private Map<String, ShadowFlowConfig> flows = Map.of();

    /**
     * To allow for the encryption of found differences you can provide options on how to encrypt. This can be done with a Cipher or via a Public Key.
     * By providing a bean of EncryptionService in your configuration you can customize it even further.
     * <p>
     * Note: it's only possible to provide one type of encryption.
     *
     * @see javax.crypto.Cipher
     * @see java.security.PublicKey
     * @see io.github.rabobank.shadow_tool.EncryptionService
     */
    @NestedConfigurationProperty
    private EncryptionProperties encryption = new EncryptionProperties();

    public Map<String, ShadowFlowConfig> getFlows() {
        return flows;
    }

    public void setFlows(final Map<String, ShadowFlowConfig> flows) {
        this.flows = flows;
    }

    public EncryptionProperties getEncryption() {
        return encryption == null ? new EncryptionProperties() : encryption;
    }

    public void setEncryption(final EncryptionProperties encryption) {
        this.encryption = encryption;
    }

    static ShadowFlowProperties bindProperties(final Environment environment) {
        return Binder.get(environment)
                .bind("shadowflow", ShadowFlowProperties.class)
                .orElseGet(ShadowFlowProperties::new);
    }

    public static class ShadowFlowConfig {
        /**
         * Percentage of how many calls should be compared in the shadow flow.
         * This should be in the range of 0-100.
         * Zero effectively disables the shadow flow (but the main flow will always run)
         */
        @PositiveOrZero(message = "A percentage needs to have a positive value between 0 (disabled) and 100")
        @Max(value = 100, message = "A percentage needs to have a positive value between 0 (disabled) and 100")
        private int percentage = 0;
        @NotBlank(message = "To create a correct ShadowFlow<T> bean the type T is required")
        private Class<?> type;

        public int getPercentage() {
            return percentage;
        }

        public void setPercentage(final int percentage) {
            this.percentage = percentage;
        }

        public Class<?> getType() {
            return type;
        }

        public void setType(final Class<?> type) {
            this.type = type;
        }
    }

    public static class EncryptionProperties {
        /**
         * @see CipherProperties
         */
        @NestedConfigurationProperty
        private CipherProperties cipher;
        /**
         * A Base 64 encoded version of a X509 Public Key.
         * This key will be used in a Cipher with algorithm "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING".
         *
         * @see javax.crypto.Cipher
         * @see java.security.spec.X509EncodedKeySpec
         */
        private String publicKey;


        /**
         * Disables encryption, but will encode differences as Base64
         */
        private boolean noop;

        public CipherProperties getCipher() {
            return cipher;
        }

        public void setCipher(final CipherProperties cipher) {
            this.cipher = cipher;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(final String publicKey) {
            this.publicKey = publicKey;
        }

        public boolean isNoop() {
            return noop;
        }

        public void setNoop(final boolean noop) {
            this.noop = noop;
        }

        public static class CipherProperties {
            /**
             * The secret should be a 16, 24 or 32 byte String.
             * <p>
             * Could be generated as follows: openssl rand -hex 32
             */
            @NotEmpty
            private String secret;
            /**
             * The secret should be a 12 byte String.
             * <p>
             * Could be generated as follows: openssl rand -hex 12
             */
            @NotEmpty
            private String initializationVector;

            public String getSecret() {
                return secret;
            }

            public void setSecret(final String secret) {
                this.secret = secret;
            }

            public String getInitializationVector() {
                return initializationVector;
            }

            public void setInitializationVector(final String initializationVector) {
                this.initializationVector = initializationVector;
            }
        }
    }
}
