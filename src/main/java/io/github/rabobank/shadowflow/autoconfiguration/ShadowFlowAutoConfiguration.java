package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow;
import io.github.rabobank.shadow_tool.ShadowFlow.ShadowFlowBuilder;
import io.github.rabobank.shadowflow.autoconfiguration.ShadowFlowProperties.EncryptionProperties.CipherProperties;
import io.github.rabobank.shadowflow.autoconfiguration.ShadowFlowProperties.ShadowFlowConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.aop.scope.ScopedProxyUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.DefaultSingletonBeanRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.core.ResolvableType;
import org.springframework.lang.NonNull;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.springframework.beans.factory.config.AutowireCapableBeanFactory.AUTOWIRE_BY_TYPE;
import static org.springframework.cloud.autoconfigure.RefreshAutoConfiguration.REFRESH_SCOPE_NAME;

@AutoConfiguration(before = RefreshAutoConfiguration.class)
@ConditionalOnClass(ShadowFlowBuilder.class)
@EnableConfigurationProperties(ShadowFlowProperties.class)
@Import(ShadowFlowAutoConfiguration.ShadowFlowRegistrar.class)
public class ShadowFlowAutoConfiguration {
    ShadowFlowAutoConfiguration() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static class ShadowFlowRegistrar implements BeanDefinitionRegistryPostProcessor, ApplicationContextAware {
        private static final String ALGORITHM = "AES";
        private static final String ALGORITHM_MODE = ALGORITHM + "/GCM-SIV/NoPadding";
        private static final int GCM_SIV_IV_SIZE = 12;
        private static final int MAC_SIZE_IN_BITS = 128;

        private ShadowFlowProperties properties;
        private ObjectProvider<EncryptionService> encryptionService;

        public ShadowFlowRegistrar() {
            Security.addProvider(new BouncyCastleProvider());
        }

        @Override
        public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
            properties = Binder.get(applicationContext.getEnvironment())
                    .bind("shadowflow", ShadowFlowProperties.class)
                    .orElseGet(ShadowFlowProperties::new);
            encryptionService = applicationContext.getBeanProvider(EncryptionService.class);
        }

        @Override
        public void postProcessBeanDefinitionRegistry(@NonNull final BeanDefinitionRegistry registry) throws BeansException {
            properties.getFlows()
                    .forEach((key, value) -> {
                        final var shadowFlowType = ResolvableType.forClassWithGenerics(ShadowFlow.class, value.getType());
                        final var definition = new RootBeanDefinition();
                        definition.setTargetType(shadowFlowType);
                        definition.setAutowireMode(AUTOWIRE_BY_TYPE);
                        definition.setAutowireCandidate(true);
                        definition.setBeanClass(ShadowFlow.class);

                        final var holder = new BeanDefinitionHolder(definition, shadowFlowBeanName(key));
                        final var proxy = ScopedProxyUtils.createScopedProxy(holder, registry, true);
                        if (registry.containsBeanDefinition(proxy.getBeanName())) {
                            registry.removeBeanDefinition(proxy.getBeanName());
                        }
                        final var beanDefinition = proxy.getBeanDefinition();
                        beanDefinition.setScope(REFRESH_SCOPE_NAME);
                        registry.registerBeanDefinition(proxy.getBeanName(), beanDefinition);
                    });
        }

        @Override
        public void postProcessBeanFactory(@NonNull final ConfigurableListableBeanFactory beanFactory) throws BeansException {
            properties.getFlows()
                    .forEach((key, value) -> {
                                final var beanName = getDecoratedBeanName(beanFactory, shadowFlowBeanName(key));
                                beanFactory.registerSingleton(beanName, createShadowFlow(key, value));
                            }
                    );
        }

        @EventListener(EnvironmentChangeEvent.class)
        public void refresh(final EnvironmentChangeEvent event) {
            if (event.getSource() instanceof final ApplicationContext appContext) {
                final var registry = (DefaultSingletonBeanRegistry) appContext.getAutowireCapableBeanFactory();
                final var beanFactory = (ConfigurableListableBeanFactory) appContext.getAutowireCapableBeanFactory();

                properties = Binder.get(appContext.getEnvironment())
                        .bind("shadowflow", ShadowFlowProperties.class)
                        .orElseGet(ShadowFlowProperties::new);
                properties.getFlows()
                        .forEach((key, value) -> {
                                    final var name = shadowFlowBeanName(key);
                                    final var beanName = getDecoratedBeanName(beanFactory, name);
                                    registry.destroySingleton(beanName);
                                    beanFactory.registerSingleton(beanName, createShadowFlow(key, value));
                                }
                        );
            }
        }

        private static String getDecoratedBeanName(final ConfigurableListableBeanFactory beanFactory, final String name) {
            final var beanDefinition = beanFactory.getBeanDefinition(name);
            final var decoratedDefinition = ((RootBeanDefinition) beanDefinition).getDecoratedDefinition();
            return Objects.requireNonNull(decoratedDefinition).getBeanName();
        }

        private static String shadowFlowBeanName(final String key) {
            return key + "-" + ShadowFlow.class.getName();
        }

        private ShadowFlow<Object> createShadowFlow(final String name, final ShadowFlowConfig config) {
            final var builder = new ShadowFlowBuilder<>(config.getPercentage())
                    .withInstanceName(name);

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
}
