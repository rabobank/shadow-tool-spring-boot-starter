package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow;
import io.github.rabobank.shadow_tool.ShadowFlow.ShadowFlowBuilder;
import io.github.rabobank.shadowflow.autoconfiguration.ShadowFlowProperties.ShadowFlowConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

import java.security.Security;
import java.util.Objects;

import static org.springframework.beans.factory.config.AutowireCapableBeanFactory.AUTOWIRE_BY_TYPE;
import static org.springframework.cloud.autoconfigure.RefreshAutoConfiguration.REFRESH_SCOPE_NAME;

@AutoConfiguration(before = RefreshAutoConfiguration.class, after = ShadowFlowEncryptionAutoConfiguration.class)
@ConditionalOnClass(ShadowFlowBuilder.class)
@EnableConfigurationProperties(ShadowFlowProperties.class)
@Import(ShadowFlowAutoConfiguration.ShadowFlowRegistrar.class)
public class ShadowFlowAutoConfiguration {
    ShadowFlowAutoConfiguration() {
    }

    static class ShadowFlowRegistrar implements BeanDefinitionRegistryPostProcessor, ApplicationContextAware {
        private ShadowFlowProperties properties;
        private ObjectProvider<EncryptionService> encryptionService;

        ShadowFlowRegistrar() {
            Security.addProvider(new BouncyCastleProvider());
        }

        @Override
        public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
            properties = ShadowFlowProperties.bindProperties(applicationContext.getEnvironment());
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
            encryptionService.ifAvailable(builder::withEncryptionService);
            return builder.build();
        }
    }
}
