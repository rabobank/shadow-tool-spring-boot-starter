package io.github.rabobank.shadowflow.autoconfiguration;

import io.github.rabobank.shadow_tool.EncryptionService;
import io.github.rabobank.shadow_tool.ShadowFlow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

import java.util.Map;

public class ShadowFlowRegistry {
    private static final Logger LOG = LoggerFactory.getLogger(ShadowFlowRegistry.class);

    private final Map<String, ShadowFlow<?>> flows;
    private final ObjectProvider<EncryptionService> encryptionService;

    ShadowFlowRegistry(final Map<String, ShadowFlow<?>> flows, final ObjectProvider<EncryptionService> encryptionService) {
        this.flows = flows;
        this.encryptionService = encryptionService;
    }

    @SuppressWarnings("unchecked")
    public <T> ShadowFlow<T> getShadowFlow(final String name) {
        return (ShadowFlow<T>) flows.computeIfAbsent(name, this::ofDefaults);
    }

    private ShadowFlow<Object> ofDefaults(final String name) {
        final var builder = new ShadowFlow.ShadowFlowBuilder<>(0)
                .withInstanceName(name);
        encryptionService.ifAvailable(builder::withEncryptionService);

        LOG.info("New ShadowFlow {} added to the registry, but this flow will be disabled by default", name);
        return builder.build();
    }
}
