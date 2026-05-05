package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.NoopEncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.lang.reflect.Field;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Set;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;

class ShadowFlowAutoConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ShadowFlowAutoConfiguration.class,
                    ShadowFlowEncryptionAutoConfiguration.class,
                    RefreshAutoConfiguration.class
            ));

    private final ApplicationContextRunner cloudlessContextRunner = new ApplicationContextRunner()
            .withClassLoader(new FilteredClassLoader(RefreshAutoConfiguration.class))
            .withConfiguration(AutoConfigurations.of(
                    ShadowFlowAutoConfiguration.class,
                    ShadowFlowEncryptionAutoConfiguration.class
            ));
    private final SecureRandom random = new SecureRandom();

    @Test
    void shouldConfigureNoShadowFlowsWithoutProperties() {
        contextRunner
                .run(context -> assertThat(context)
                        .doesNotHaveBean(ShadowFlow.class)
                        .doesNotHaveBean("shadowFlowTypeHint"));
    }

    @Test
    void shouldConfigureShadowFlowTypeHintWhenFlowsAreConfigured() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String"
                )
                .run(context -> assertThat(context).hasBean("shadowFlowTypeHint"));
    }

    @Test
    void shouldConfigureShadowFlows() {
        contextRunner
                .withPropertyValues("shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String")
                .run(context ->
                        assertThat(context).hasBean("test")
                                .hasBean("scopedTarget.test")
                                .doesNotHaveBean(EncryptionService.class));
    }

    @Test
    void shouldConfigureMultipleShadowFlows() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.flow1.percentage=50",
                        "shadowflow.flows.flow1.type=java.lang.String",
                        "shadowflow.flows.flow2.percentage=75",
                        "shadowflow.flows.flow2.type=java.lang.Integer"
                )
                .run(context -> assertThat(context)
                        .hasBean("flow1")
                        .hasBean("flow2")
                        .hasBean("scopedTarget.flow1")
                        .hasBean("scopedTarget.flow2"));
    }

    @Test
    void shouldAddShadowFlowBeanOnEnvironmentRefresh() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.flow1.percentage=50",
                        "shadowflow.flows.flow1.type=java.lang.String"
                )
                .run(context -> {
                    assertThat(context).hasBean("flow1").doesNotHaveBean("flow2");

                    TestPropertyValues.of(
                            "shadowflow.flows.flow2.percentage=25",
                            "shadowflow.flows.flow2.type=java.lang.Long"
                    ).applyTo(context.getEnvironment());
                    context.publishEvent(new EnvironmentChangeEvent(context, Set.of("shadowflow.flows.flow2")));

                    assertThat(context)
                            .hasBean("flow1")
                            .hasBean("flow2")
                            .hasBean("scopedTarget.flow2");
                });
    }

    @Test
    void shouldConfigureShadowFlowsCloudless() {
        cloudlessContextRunner
                .withPropertyValues("shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String")
                .run(context ->
                        assertThat(context).hasBean("test")
                                .doesNotHaveBean("scopedTarget.test")
                                .doesNotHaveBean(EncryptionService.class));
    }

    @Test
    void shouldConfigureShadowFlowTypeHintCloudlessWhenFlowsAreConfigured() {
        cloudlessContextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String"
                )
                .run(context -> assertThat(context).hasBean("shadowFlowTypeHint"));
    }

    @Test
    void shouldNotConfigureShadowFlowTypeHintCloudlessWithoutFlows() {
        cloudlessContextRunner
                .run(context -> assertThat(context).doesNotHaveBean("shadowFlowTypeHint"));
    }

    @Test
    void shouldConfigureShadowFlowsWithEncryptionService() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String",
                        "shadowflow.encryption.noop=true"
                )
                .run(context ->
                        assertThat(context).hasBean("test")
                                .hasBean("scopedTarget.test")
                                .hasSingleBean(EncryptionService.class)
                                .hasSingleBean(NoopEncryptionService.class));
    }

    @Test
    void shouldConfigureShadowFlowWithCustomExecutorBean() {
        contextRunner
                .withUserConfiguration(CustomExecutorConfiguration.class)
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String",
                        "shadowflow.executor-bean-name=customShadowFlowExecutor"
                )
                .run(context -> {
                    assertThat(context).hasBean("test").hasBean("scopedTarget.test");
                    final var flow = (ShadowFlow<?>) context.getBean("scopedTarget.test");
                    final var configuredExecutor = context.getBean("customShadowFlowExecutor", Executor.class);
                    assertThat(getExecutor(flow)).isSameAs(configuredExecutor);
                });
    }

    @Test
    void shouldFailWhenConfiguredExecutorBeanDoesNotExist() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String",
                        "shadowflow.executor-bean-name=missingExecutor"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void shouldConfigureShadowFlowsWithCipher() {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String",
                        "shadowflow.encryption.cipher.secret=" + randomBytes(32),
                        "shadowflow.encryption.cipher.initialization-vector=" + randomBytes(12)
                )
                .run(context -> assertThat(context).hasBean("test")
                        .hasBean("scopedTarget.test")
                        .hasBean("defaultEncryptionService"));
    }

    @Test
    void shouldConfigureShadowFlowsWithPublicKey() throws NoSuchAlgorithmException {
        contextRunner
                .withPropertyValues(
                        "shadowflow.flows.test.percentage=50",
                        "shadowflow.flows.test.type=java.lang.String",
                        "shadowflow.encryption.public-key=" + generatePublicKey()
                )
                .run(context -> assertThat(context).hasBean("test")
                        .hasBean("scopedTarget.test")
                        .hasBean("publicKeyEncryptionService"));
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

    private static Executor getExecutor(final ShadowFlow<?> shadowFlow) {
        try {
            final Field executorField = ShadowFlow.class.getDeclaredField("executor");
            executorField.setAccessible(true);
            return (Executor) executorField.get(shadowFlow);
        } catch (NoSuchFieldException | IllegalAccessException exception) {
            throw new IllegalStateException("Unable to read configured executor from ShadowFlow", exception);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomExecutorConfiguration {
        @Bean("customShadowFlowExecutor")
        Executor customShadowFlowExecutor() {
            return Runnable::run;
        }
    }
}
