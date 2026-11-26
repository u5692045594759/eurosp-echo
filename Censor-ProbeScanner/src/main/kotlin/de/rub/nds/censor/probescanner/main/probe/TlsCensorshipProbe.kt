package de.rub.nds.censor.probescanner.main.probe;

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.extension.EchExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.EsniExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.EncryptedClientHelloVersion
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

class TlsCensorshipProbe(private val config: CensorScannerConfig) : CensorProbe(CensorProbeType.TLS) {

    private var blocksSNI = 0
    private var blocksESNI = 0
    private var blocksECH = 0

    init {
        register(
            CensorAnalyzedProperty.BLOCKS_SNI,
            CensorAnalyzedProperty.BLOCKS_ESNI,
            CensorAnalyzedProperty.BLOCKS_ECH
        )
    }

    override fun getRequirements(): Requirement<CensorReport> {
        return FulfilledRequirement()
    }

    override fun adjustConfig(censorReport: CensorReport) {
    }

    /**
     * Scans for SNI-based censorship
     */
    override fun executeTest() {
        runBlocking(Dispatchers.IO) {
            // simply open a TLS connection to the server and see whether the handshake executes
            blocksSNI = countBlocked("SNI", tcpWait(config)) {
                getDefaultTlsConnection(it).apply { registerManipulations(SniExtensionManipulation(config.hostname, true)) }
            }
            blocksESNI = countBlocked("ESNI", tcpWait(config, config.waitEsni ?: config.wait)) {
                getDefaultTlsConnection(it).apply { registerManipulations(EsniExtensionManipulation(true)) }
            }
            blocksECH = countBlocked("ECH", tcpWait(config)) {
                getDefaultTlsConnection(it).apply { registerManipulations(EchExtensionManipulation(config.hostname, EncryptedClientHelloVersion.DRAFT_13_14_15_16_17, true)) }
            }
        }
    }

    fun getDefaultTlsConnection(pcapCapturer: PcapCapturer): TlsConnection {
        return TlsConnection(
            config.getIpAddress(),
            if (config.echo) 7 else 443,
            config.timeout,
            if (config.echo) CensorScanType.ECHO else CensorScanType.SIMPLE,
            pcapCapturer = pcapCapturer,
            hostname = config.hostname,
            clientPort = if (config.mimicClientPort) 443 else -1
        )
    }

    override fun mergeData(censorReport: CensorReport) {
        put(CensorAnalyzedProperty.BLOCKS_SNI, IntegerResult(CensorAnalyzedProperty.BLOCKS_SNI, blocksSNI))
        put(CensorAnalyzedProperty.BLOCKS_ESNI, IntegerResult(CensorAnalyzedProperty.BLOCKS_ESNI, blocksESNI))
        put(CensorAnalyzedProperty.BLOCKS_ECH, IntegerResult(CensorAnalyzedProperty.BLOCKS_ECH, blocksECH))
    }
}
