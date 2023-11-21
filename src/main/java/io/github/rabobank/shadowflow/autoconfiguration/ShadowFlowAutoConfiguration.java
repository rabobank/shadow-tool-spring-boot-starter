package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow;
import io.github.rabobank.shadow_tool.ShadowFlow.ShadowFlowBuilder;
import io.github.rabobank.shadowflow.autoconfiguration.ShadowFlowProperties.EncryptionProperties.CipherProperties;
import io.github.rabobank.shadowflow.autoconfiguration.ShadowFlowProperties.ShadowFlowConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.cloud.context.scope.refresh.RefreshScopeRefreshedEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

@AutoConfiguration
@ConditionalOnClass(ShadowFlowBuilder.class)
@EnableConfigurationProperties(ShadowFlowProperties.class)
public class ShadowFlowAutoConfiguration {
    private static final int GCM_SIV_IV_SIZE = 12;
    private static final int MAC_SIZE_IN_BITS = 128;
    private static final String ALGORITHM = "AES";
    private static final String ALGORITHM_MODE = ALGORITHM + "/GCM-SIV/NoPadding";

    private final AtomicBoolean needsInit = new AtomicBoolean(true);

    private final ShadowFlowProperties properties;
    private final ObjectProvider<EncryptionService> encryptionService;
    private final ObjectProvider<ShadowFlow<?>> shadowFlows;
    private ShadowFlowRegistry shadowFlowRegistry;

    ShadowFlowAutoConfiguration(final ShadowFlowProperties properties,
                                final ObjectProvider<EncryptionService> encryptionService,
                                final ObjectProvider<ShadowFlow<?>> shadowFlows) {
        Security.addProvider(new BouncyCastleProvider());

        this.properties = properties;
        this.shadowFlows = shadowFlows;
        this.encryptionService = encryptionService;
    }

    @Bean
    @RefreshScope
    ShadowFlowRegistry shadowFlowRegistry() {
        init();
        return shadowFlowRegistry;
    }

    @EventListener({ApplicationPreparedEvent.class, EnvironmentChangeEvent.class, RefreshScopeRefreshedEvent.class})
    @Order(HIGHEST_PRECEDENCE)
    public void onApplicationEvent(@NonNull final ApplicationEvent event) {
        if (!(event instanceof ApplicationPreparedEvent) && !(event instanceof RefreshScopeRefreshedEvent)) {
            if (event instanceof final EnvironmentChangeEvent environmentChangeEvent) {
                needsInit.compareAndSet(false, environmentChangeEvent.getKeys().stream()
                        .anyMatch(key -> key.startsWith("shadowflow")));
            }
        } else {
            init();
        }
    }

    private void init() {
        if (needsInit.compareAndSet(true, false)) {
            final Map<String, ShadowFlow<?>> flows = properties.getFlows().entrySet().stream()
                    .collect(Collectors.toMap(Map.Entry::getKey, this::createShadowFlow));

            flows.putAll(shadowFlows.stream().collect(Collectors.toMap(ShadowFlow::getInstanceName, Function.identity())));

            shadowFlowRegistry = new ShadowFlowRegistry(flows, encryptionService);
        }
    }

    private ShadowFlow<Object> createShadowFlow(final Map.Entry<String, ShadowFlowConfig> flow) {
        final var builder = new ShadowFlowBuilder<>(flow.getValue().getPercentage())
                .withInstanceName(flow.getKey());

        final var cipherProperties = properties.getEncryption().getCipher();
        if (cipherProperties != null) {
            builder.withCipher(createCipher(cipherProperties));
        }
        if (properties.getEncryption().getPublicKey() != null) {
            builder.withEncryption(getPublicKey(properties.getEncryption().getPublicKey()));
        }
        encryptionService.ifAvailable(builder::withEncryptionService);

        return builder.build();
    }

    private Cipher createCipher(final CipherProperties cipherProperties) {
        try {
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
            return cipher;
        } catch (final GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to configure the cipher", e);
        }
    }

    private PublicKey getPublicKey(final String publicKey) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.decode(publicKey)));
        } catch (final GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
