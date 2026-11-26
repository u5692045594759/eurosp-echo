package de.rub.nds.censor.probescanner.main.constants

import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory

/**
 * Categories of [CensorAnalyzedProperty].
 */
enum class CensorAnalyzedPropertyCategory: AnalyzedPropertyCategory {
    TLS,
    HTTP,
    TCP,
    DNS,
    QUIC
}