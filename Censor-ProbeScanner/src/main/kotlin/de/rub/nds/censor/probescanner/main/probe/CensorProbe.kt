package de.rub.nds.censor.probescanner.main.probe

import de.rub.nds.censor.core.connection.Connection
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.probescanner.main.config.CensorScannerConfig
import de.rub.nds.censor.probescanner.main.constants.CensorProbeType
import de.rub.nds.censor.probescanner.main.report.CensorReport
import de.rub.nds.scanner.core.probe.ScannerProbe
import de.rub.nds.tlsattacker.core.state.State
import kotlinx.coroutines.delay

/**
 * Abstract super class for probes. Each probes analyses a distinct feature of censorship behavior.
 */
abstract class CensorProbe(private val probeType: CensorProbeType): ScannerProbe<CensorReport, State>(probeType) {

    override fun getType(): CensorProbeType {
        return probeType
    }

    protected suspend fun <M> countBlocked(label: String, waitSeconds: Int, createConnection: (PcapCapturer) -> Connection<M>): Int {
        val results = mutableListOf<ConnectionReturn>()
        printProgress(label, results)
        try {
            repeat(REPETITIONS) {
                val result = PcapCapturer(bpfExpression = "tcp or udp").use { pcapCapturer ->
                    pcapCapturer.start()
                    try {
                        createConnection(pcapCapturer).connect()
                        ConnectionReturn.WORKING
                    } catch (e: NotConnectableException) {
                        e.reason
                    }
                }
                results.add(result)
                printProgress(label, results)
                delay(waitSeconds * 1000L)
            }
        } finally {
            println()
        }
        return results.count { it != ConnectionReturn.WORKING }
    }

    protected fun tcpWait(config: CensorScannerConfig, wait: Int = config.wait): Int {
        return wait + if (config.mimicClientPort) MIMIC_TCP_WAIT_SECONDS else 0
    }

    private fun printProgress(label: String, results: List<ConnectionReturn>) {
        val done = results.size
        print("\r%-15s [%s%s] %2d/%d  %s".format(label, "#".repeat(done), ".".repeat(REPETITIONS - done), done, REPETITIONS, results.joinToString(" ")))
        System.out.flush()
    }

    companion object {
        const val REPETITIONS = 10
        const val MIMIC_TCP_WAIT_SECONDS = 15
    }
}
