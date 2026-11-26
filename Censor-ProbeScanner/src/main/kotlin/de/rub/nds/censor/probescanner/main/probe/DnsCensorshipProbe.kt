package de.rub.nds.censor.probescanner.main.probe

import de.rub.nds.censor.core.connection.UdpDataConnection
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.probescanner.main.config.CensorScannerConfig
import de.rub.nds.censor.probescanner.main.constants.CensorAnalyzedProperty
import de.rub.nds.censor.probescanner.main.constants.CensorProbeType
import de.rub.nds.censor.probescanner.main.report.CensorReport
import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement
import de.rub.nds.scanner.core.probe.requirements.Requirement
import de.rub.nds.scanner.core.probe.result.IntegerResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

class DnsCensorshipProbe(private val config: CensorScannerConfig) : CensorProbe(CensorProbeType.DNS) {
    private var blocksDnsRequest = 0
    private var blocksDnsResponse = 0

    init {
        register(
            CensorAnalyzedProperty.BLOCKS_DNS_REQUEST,
            CensorAnalyzedProperty.BLOCKS_DNS_RESPONSE,
        )
    }

    override fun getRequirements(): Requirement<CensorReport> {
        return FulfilledRequirement()
    }

    override fun adjustConfig(censorReport: CensorReport) {
    }

    /**
     * Scans for DNS-based censorship
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun executeTest() {
        runBlocking(Dispatchers.IO) {
            // send DNS-based censorship test vectors
            blocksDnsRequest = countBlocked("DNS Request", config.wait) {
                prepareUdpDataConnection("167d01000001000000000001${config.getDnsHostnameAsHex()}0001000100002905c0000000000000".hexToByteArray(), it)
            }

            blocksDnsResponse = countBlocked("DNS Response", config.wait) {
                prepareUdpDataConnection("faf681800001000100000001${config.getDnsHostnameAsHex()}00010001c00c000100010000012c0004b90f3be00000290200000000000000".hexToByteArray(), it)
            }
        }
    }

    private fun prepareUdpDataConnection(data: ByteArray, pcapCapturer: PcapCapturer): UdpDataConnection {
        return UdpDataConnection(
            config.getIpAddress(),
            if (config.echo) 7 else 53,
            config.timeout,
            echo = config.echo,
            pcapCapturer = pcapCapturer,
            data = data,
            clientPort = if (config.mimicClientPort) 53 else -1
        )
    }

    override fun mergeData(censorReport: CensorReport) {
        put(CensorAnalyzedProperty.BLOCKS_DNS_REQUEST, IntegerResult(CensorAnalyzedProperty.BLOCKS_DNS_REQUEST, blocksDnsRequest))
        put(CensorAnalyzedProperty.BLOCKS_DNS_RESPONSE, IntegerResult(CensorAnalyzedProperty.BLOCKS_DNS_RESPONSE, blocksDnsResponse))
    }
}