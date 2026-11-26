package de.rub.nds.censor.probescanner.main.report

import de.rub.nds.censor.probescanner.main.constants.CensorAnalyzedProperty
import de.rub.nds.censor.probescanner.main.probe.CensorProbe
import de.rub.nds.scanner.core.config.ScannerDetail
import de.rub.nds.scanner.core.report.PrintingScheme
import de.rub.nds.scanner.core.report.ReportPrinter
import java.lang.StringBuilder

/**
 * Prints the [CensorReport] in human-readable form.
 */
class CensorReportPrinter(report: CensorReport, detail: ScannerDetail, scheme: PrintingScheme, printColorful: Boolean): ReportPrinter<CensorReport>(detail, scheme, printColorful, report) {

    override fun getFullReport(): String {
        val builder = StringBuilder()
        appendResults(builder)
        return builder.toString()
    }

    private fun appendResults(builder: StringBuilder) {
        appendBlockedCount(builder, "Blocks SNI", CensorAnalyzedProperty.BLOCKS_SNI)
        appendBlockedCount(builder, "Blocks ESNI", CensorAnalyzedProperty.BLOCKS_ESNI)
        appendBlockedCount(builder, "Blocks ECH", CensorAnalyzedProperty.BLOCKS_ECH)
        appendBlockedCount(builder, "Blocks HTTP(Path)", CensorAnalyzedProperty.BLOCKS_PATH)
        appendBlockedCount(builder, "Blocks HTTP(Host)", CensorAnalyzedProperty.BLOCKS_HOST)
        appendBlockedCount(builder, "Blocks HTTP(Response)", CensorAnalyzedProperty.BLOCKS_RESPONSE)
        appendBlockedCount(builder, "Blocks TCP/IP in TCP", CensorAnalyzedProperty.BLOCKS_TCP)
        appendBlockedCount(builder, "Blocks DNS Request", CensorAnalyzedProperty.BLOCKS_DNS_REQUEST)
        appendBlockedCount(builder, "Blocks DNS Response", CensorAnalyzedProperty.BLOCKS_DNS_RESPONSE)
        appendBlockedCount(builder, "Blocks QUIC SNI", CensorAnalyzedProperty.BLOCKS_QUIC)
    }

    private fun appendBlockedCount(builder: StringBuilder, name: String, property: CensorAnalyzedProperty) {
        val blocked = report.getIntegerResult(property)?.value
        prettyAppend(builder, name, if (blocked == null) "not tested" else "$blocked/${CensorProbe.REPETITIONS}")
    }
}
