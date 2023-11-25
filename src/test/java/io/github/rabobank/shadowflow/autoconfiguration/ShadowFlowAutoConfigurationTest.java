package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.NoopEncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

class ShadowFlowAutoConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ShadowFlowAutoConfiguration.class,
                    ShadowFlowEncryptionAutoConfiguration.class,
                    RefreshAutoConfiguration.class
            ));
    private final SecureRandom random = new SecureRandom();

    @Test
    void shouldConfigureNoShadowFlowsWithoutProperties() {
        contextRunner
                .run(context -> assertThat(context).doesNotHaveBean(ShadowFlow.class));
    }

    @Test
    void shouldConfigureShadowFlows() {
        contextRunner
                .withPropertyValues("shadowflow.flows.test.percentage=50")
                .run(context ->
                        assertThat(context).hasBean("test-" + ShadowFlow.class.getName())
                                .hasBean("scopedTarget.test-" + ShadowFlow.class.getName())
                                .doesNotHaveBean(EncryptionService.class));
    }

    @Test
    void shouldConfigureShadowFlowsWithEncryptionService() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.encryption.noop=true"
                )
                .run(context ->
                        assertThat(context).hasBean("test-" + ShadowFlow.class.getName())
                                .hasBean("scopedTarget.test-" + ShadowFlow.class.getName())
                                .hasSingleBean(EncryptionService.class)
                                .hasSingleBean(NoopEncryptionService.class));
    }

    @Test
    void shouldConfigureShadowFlowsWithCipher() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.encryption.cipher.secret=" + randomBytes(32),
                        "shadowflow.encryption.cipher.initialization-vector=" + randomBytes(12)
                )
                .run(context -> {
                    assertThat(context).hasBean("test-" + ShadowFlow.class.getName())
                            .hasBean("scopedTarget.test-" + ShadowFlow.class.getName())
                            .hasBean("defaultEncryptionService");
                });
    }

    @Test
    void shouldConfigureShadowFlowsWithPublicKey() throws NoSuchAlgorithmException {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.encryption.public-key=" + generatePublicKey()
                )
                .run(context -> {
                    assertThat(context).hasBean("test-" + ShadowFlow.class.getName())
                            .hasBean("scopedTarget.test-" + ShadowFlow.class.getName())
                            .hasBean("publicKeyEncryptionService");
                });
    }

    @Test
    void configuringDifferentFormOfEncryptionShouldNotBeAllowed() throws NoSuchAlgorithmException {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.encryption.cipher.secret=" + randomBytes(32),
                        "shadowflow.encryption.cipher.initialization-vector=" + randomBytes(12),
                        "shadowflow.encryption.public-key=" + generatePublicKey()
                )
                .run(context -> assertThat(context).hasFailed());
    }

    private String randomBytes(final int length) {
        final var randomBytes = new byte[length];
        random.nextBytes(randomBytes);
        return Hex.encodeHexString(randomBytes);
    }

    private static String generatePublicKey() throws NoSuchAlgorithmException {
        // Generate a key pair (public and private keys)
        final var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can adjust the key size as needed
        final var keyPair = keyPairGenerator.generateKeyPair();

        // Get the public key from the key pair
        final var publicKey = keyPair.getPublic();

        // Encode the public key in Base64
        return Base64.encodeBase64String(publicKey.getEncoded());
    }
}
