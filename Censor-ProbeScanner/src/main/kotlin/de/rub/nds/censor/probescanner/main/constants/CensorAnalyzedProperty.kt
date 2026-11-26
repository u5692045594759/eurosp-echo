package de.rub.nds.censor.probescanner.main.constants

import de.rub.nds.scanner.core.probe.AnalyzedProperty
import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory

/**
 * Holds properties evaluates by CensorScanner.
 */
enum class CensorAnalyzedProperty(private val propertyCategory: CensorAnalyzedPropertyCategory): AnalyzedProperty {
    // DNS
    BLOCKS_DNS_REQUEST(CensorAnalyzedPropertyCategory.DNS),
    BLOCKS_DNS_RESPONSE(CensorAnalyzedPropertyCategory.DNS),

    // TLS
    BLOCKS_SNI(CensorAnalyzedPropertyCategory.TLS),
    BLOCKS_ESNI(CensorAnalyzedPropertyCategory.TLS),
    BLOCKS_ECH(CensorAnalyzedPropertyCategory.TLS),

    // HTTP
    BLOCKS_PATH(CensorAnalyzedPropertyCategory.HTTP),
    BLOCKS_HOST(CensorAnalyzedPropertyCategory.HTTP),
    BLOCKS_RESPONSE(CensorAnalyzedPropertyCategory.HTTP),

    // TCP
    BLOCKS_TCP(CensorAnalyzedPropertyCategory.TCP),

    // QUIC
    BLOCKS_QUIC(CensorAnalyzedPropertyCategory.QUIC);

    override fun getCategory(): AnalyzedPropertyCategory {
        return propertyCategory
    }

    override fun getName(): String {
        return name
    }
}