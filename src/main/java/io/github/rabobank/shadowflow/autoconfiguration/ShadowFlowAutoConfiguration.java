package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow;
import io.github.rabobank.shadow_tool.ShadowFlow.ShadowFlowBuilder;
import io.github.rabobank.shadowflow.autoconfiguration.ShadowFlowProperties.ShadowFlowConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jspecify.annotations.NonNull;
import org.springframework.aop.scope.ScopedProxyUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.core.ResolvableType;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.security.Security;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.springframework.beans.factory.config.AutowireCapableBeanFactory.AUTOWIRE_BY_TYPE;

@AutoConfiguration(beforeName = "org.springframework.cloud.autoconfigure.RefreshAutoConfiguration", after = ShadowFlowEncryptionAutoConfiguration.class)
@ConditionalOnClass(ShadowFlowBuilder.class)
@EnableConfigurationProperties(ShadowFlowProperties.class)
@Import(ShadowFlowAutoConfiguration.ShadowFlowRegistrar.class)
public class ShadowFlowAutoConfiguration {

    private static final String REFRESH_SCOPE_BEAN_NAME = "refreshScope";
    private static final String REFRESH_SCOPE = "refresh";
    private static final String PROPERTY_SHADOW_FLOWS = "shadowflow.flows";

    ShadowFlowAutoConfiguration() {
    }

    /**
     * Exposes a non-autowire-candidate {@link ShadowFlow} bean so IDE inspections can discover
     * that ShadowFlow beans exist even though per-flow beans are registered dynamically at runtime.
     * <p>
     * This bean is only created when at least one {@code shadowflow.flows[*]} entry is configured.
     */
    @Bean(name = "shadowFlowTypeHint", autowireCandidate = false)
    @Conditional(ShadowFlowConfiguredCondition.class)
    ShadowFlow<?> shadowFlowTypeHint() {
        return new ShadowFlowBuilder<>(0)
                .withInstanceName("shadowFlowTypeHint")
                .build();
    }

    /**
     * Checks whether at least one shadow flow is configured.
     */
    static final class ShadowFlowConfiguredCondition implements Condition {
        @Override
        public boolean matches(@NonNull final ConditionContext context, @NonNull final AnnotatedTypeMetadata metadata) {
            return Binder.get(context.getEnvironment())
                    .bind(PROPERTY_SHADOW_FLOWS, Bindable.mapOf(String.class, ShadowFlowConfig.class))
                    .map(flows -> !flows.isEmpty())
                    .orElse(false);
        }
    }

    static class ShadowFlowRegistrar implements BeanDefinitionRegistryPostProcessor, ApplicationContextAware {
        private ApplicationContext applicationContext;
        private ObjectProvider<EncryptionService> encryptionService;
        private final Set<String> registeredFlows = new HashSet<>();

        ShadowFlowRegistrar() {
            Security.addProvider(new BouncyCastleProvider());
        }

        @Override
        public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
            this.applicationContext = applicationContext;
            encryptionService = applicationContext.getBeanProvider(EncryptionService.class);
        }

        @Override
        public void postProcessBeanDefinitionRegistry(@NonNull final BeanDefinitionRegistry registry) throws BeansException {
            final var flows = currentFlowConfig();
            flows.keySet().forEach(flowName -> registerFlowBeanDefinition(registry, flowName));
            registeredFlows.clear();
            registeredFlows.addAll(flows.keySet());
        }


        @Override
        public void postProcessBeanFactory(@NonNull final ConfigurableListableBeanFactory beanFactory) throws BeansException {
            // Bean instances are created from bean-definition suppliers.
        }

        @EventListener(EnvironmentChangeEvent.class)
        public void refresh(final EnvironmentChangeEvent event) {
            if (event.getKeys().stream().noneMatch(key -> key.startsWith(PROPERTY_SHADOW_FLOWS))) {
                return;
            }
            if (applicationContext == null) {
                return;
            }
            final var beanFactory = applicationContext.getAutowireCapableBeanFactory();
            if (!(beanFactory instanceof final BeanDefinitionRegistry registry)) {
                return;
            }

            final var flows = currentFlowConfig();
            final var flowNames = flows.keySet();
            final var removedFlows = new HashSet<>(registeredFlows);
            removedFlows.removeAll(flowNames);

            removedFlows.forEach(flowName -> unregisterFlowBeanDefinition(registry, flowName));
            flowNames.stream()
                    .filter(flowName -> !registeredFlows.contains(flowName))
                    .forEach(flowName -> registerFlowBeanDefinition(registry, flowName));

            registeredFlows.clear();
            registeredFlows.addAll(flowNames);
        }

        private Map<String, ShadowFlowConfig> currentFlowConfig() {
            if (applicationContext == null) {
                return Map.of();
            }
            return Binder.get(applicationContext.getEnvironment())
                    .bind(PROPERTY_SHADOW_FLOWS, Bindable.mapOf(String.class, ShadowFlowConfig.class))
                    .orElseGet(Map::of);
        }

        private ShadowFlowConfig getFlowConfig(final String flowName) {
            return Objects.requireNonNull(currentFlowConfig().get(flowName), () -> "No shadow flow config found for bean '" + flowName + "'");
        }

        private void registerFlowBeanDefinition(final BeanDefinitionRegistry registry, final String flowName) {
            final var definition = new RootBeanDefinition(ShadowFlow.class);
            definition.setTargetType(ResolvableType.forClassWithGenerics(ShadowFlow.class, getFlowConfig(flowName).getType()));
            definition.setAutowireMode(AUTOWIRE_BY_TYPE);
            definition.setAutowireCandidate(true);
            definition.setInstanceSupplier(() -> createShadowFlow(flowName, getFlowConfig(flowName)));

            if (registry.containsBeanDefinition(flowName)) {
                registry.removeBeanDefinition(flowName);
            }

            if (registry.containsBeanDefinition(scopedTargetBeanName(flowName))) {
                registry.removeBeanDefinition(scopedTargetBeanName(flowName));
            }

            if (registry.containsBeanDefinition(REFRESH_SCOPE_BEAN_NAME)) {
                definition.setScope(REFRESH_SCOPE);
                final var holder = new BeanDefinitionHolder(definition, flowName);
                final var proxy = ScopedProxyUtils.createScopedProxy(holder, registry, true);
                if (registry.containsBeanDefinition(proxy.getBeanName())) {
                    registry.removeBeanDefinition(proxy.getBeanName());
                }
                registry.registerBeanDefinition(proxy.getBeanName(), proxy.getBeanDefinition());
                return;
            }

            registry.registerBeanDefinition(flowName, definition);
        }

        private void unregisterFlowBeanDefinition(final BeanDefinitionRegistry registry, final String flowName) {
            if (registry.containsBeanDefinition(flowName)) {
                registry.removeBeanDefinition(flowName);
            }

            final var targetBeanName = scopedTargetBeanName(flowName);
            if (registry.containsBeanDefinition(targetBeanName)) {
                registry.removeBeanDefinition(targetBeanName);
            }
        }

        private static String scopedTargetBeanName(final String name) {
            return "scopedTarget." + name;
        }

        private ShadowFlow<Object> createShadowFlow(final String name, final ShadowFlowConfig config) {
            final var builder = new ShadowFlowBuilder<>(config.getPercentage())
                    .withInstanceName(name);
            encryptionService.ifAvailable(builder::withEncryptionService);
            return builder.build();
        }
    }
}
