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
import org.springframework.context.annotation.Bean;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

class ShadowFlowAutoConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ShadowFlowAutoConfiguration.class,
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
                .withUserConfiguration(NoopEncryptionTestConfiguration.class)
                .withPropertyValues("shadowflow.flows.test.percentage=50")
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
                            .hasBean("scopedTarget.test-" + ShadowFlow.class.getName());

                    final var shadowFlow = context.getBean(ShadowFlow.class);
                    final var encryptionService = ReflectionTestUtils.getField(shadowFlow, "encryptionService");
                    assertThat(encryptionService).isInstanceOf(EncryptionService.class);
                    assertThat(encryptionService).isNotInstanceOf(NoopEncryptionService.class);
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
                            .hasBean("scopedTarget.test-" + ShadowFlow.class.getName());

                    final var shadowFlow = context.getBean(ShadowFlow.class);
                    final var encryptionService = ReflectionTestUtils.getField(shadowFlow, "encryptionService");
                    assertThat(encryptionService).isInstanceOf(EncryptionService.class);
                    assertThat(encryptionService).isNotInstanceOf(NoopEncryptionService.class);
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

    private static class NoopEncryptionTestConfiguration {
        @Bean
        EncryptionService noopEncryption() {
            return NoopEncryptionService.INSTANCE;
        }
    }
}
