package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.DefaultEncryptionService;
import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.NoopEncryptionService;
import io.github.rabobank.shadow_tool.PublicKeyEncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow.ShadowFlowBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

import static javax.crypto.Cipher.ENCRYPT_MODE;

@AutoConfiguration(before = ShadowFlowAutoConfiguration.class)
@ConditionalOnClass(ShadowFlowBuilder.class)
@EnableConfigurationProperties(ShadowFlowProperties.class)
class ShadowFlowEncryptionAutoConfiguration {
    private static final String ALGORITHM = "AES";
    private static final String ALGORITHM_MODE = ALGORITHM + "/GCM-SIV/NoPadding";
    private static final int GCM_SIV_IV_SIZE = 12;
    private static final int MAC_SIZE_IN_BITS = 128;

    ShadowFlowEncryptionAutoConfiguration() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Bean
    @ConditionalOnProperty("shadowflow.encryption.noop")
    EncryptionService noopEncryptionService() {
        return NoopEncryptionService.INSTANCE;
    }

    @Bean
    @RefreshScope
    @ConditionalOnProperty("shadowflow.encryption.public-key")
    EncryptionService publicKeyEncryptionService(final Environment environment) throws GeneralSecurityException {
        final var properties = ShadowFlowProperties.bindProperties(environment);

        final var publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.decode(properties.getEncryption().getPublicKey())));
        return new PublicKeyEncryptionService(publicKey);
    }

    @Bean
    @RefreshScope
    @ConditionalOnProperty("shadowflow.encryption.cipher.secret")
    EncryptionService defaultEncryptionService(final Environment environment) throws GeneralSecurityException {
        final var properties = ShadowFlowProperties.bindProperties(environment);

        final var cipherProperties = properties.getEncryption().getCipher();
        // The AES key (16, 24, or 32 bytes)
        final var keyBytes = Hex.decodeStrict(cipherProperties.getSecret());
        final var secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        // Initialization Vector (IV) for GCM
        final var iv = Hex.decodeStrict(cipherProperties.getInitializationVector()); // 96 bits IV
        if (iv.length != GCM_SIV_IV_SIZE) {
            throw new IllegalArgumentException("Initialization Vector should be 12 bytes / 96 bits");
        }

        // Create AEADParameterSpec
        final var gcmParameterSpec = new GCMParameterSpec(MAC_SIZE_IN_BITS, iv);
        // Create Cipher instance with the specified algorithm and provider
        final var cipher = Cipher.getInstance(ALGORITHM_MODE);

        // Initialize the Cipher for encryption or decryption
        cipher.init(ENCRYPT_MODE, secretKey, gcmParameterSpec);
        return new DefaultEncryptionService(cipher);
    }
}
