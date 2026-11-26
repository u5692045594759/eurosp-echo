package de.rub.nds.censor.probescanner.main.probe

import de.rub.nds.censor.core.connection.TcpDataConnection
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

class HttpCensorshipProbe(private val config: CensorScannerConfig) : CensorProbe(CensorProbeType.HTTP) {
    private var blocksPath = 0
    private var blocksHost = 0
    private var blocksResponse = 0

    init {
        register(
            CensorAnalyzedProperty.BLOCKS_PATH,
            CensorAnalyzedProperty.BLOCKS_HOST,
            CensorAnalyzedProperty.BLOCKS_RESPONSE
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
            // send HTTP-based test vectors for path- and Host-based censorship
            val pathData = "GET ${config.path} HTTP/1.1\r\n" +
                    "Host: harmless.com\r\n" +
                    "\r\n"
            blocksPath = countBlocked("HTTP(Path)", tcpWait(config)) {
                prepareTcpDataConnection(pathData.toByteArray(Charsets.ISO_8859_1), it)
            }

            val hostData = "GET / HTTP/1.1\r\n" +
                    "Host: ${config.hostname}\r\n" +
                    "\r\n"
            blocksHost = countBlocked("HTTP(Host)", tcpWait(config)) {
                prepareTcpDataConnection(hostData.toByteArray(Charsets.ISO_8859_1), it)
            }

            val responseData = "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/html; charset=ISO-8859-1\r\n" +
                    "Content-Length: ${1 + config.hostname.length + config.path.length}\r\n" +
                    "\r\n" +
                    "${config.hostname} ${config.path}"// Body with keywords
            blocksResponse = countBlocked("HTTP(Response)", tcpWait(config)) {
                prepareTcpDataConnection(responseData.toByteArray(Charsets.ISO_8859_1), it)
            }
        }
    }

    private fun prepareTcpDataConnection(data: ByteArray, pcapCapturer: PcapCapturer): TcpDataConnection {
        return TcpDataConnection(
            config.getIpAddress(),
            if (config.echo) 7 else 80,
            config.timeout,
            echo = config.echo,
            clientPort = if (config.mimicClientPort) 80 else -1,
            pcapCapturer = pcapCapturer,
            data = data
        )
    }

    override fun mergeData(censorReport: CensorReport) {
        put(CensorAnalyzedProperty.BLOCKS_PATH, IntegerResult(CensorAnalyzedProperty.BLOCKS_PATH, blocksPath))
        put(CensorAnalyzedProperty.BLOCKS_HOST, IntegerResult(CensorAnalyzedProperty.BLOCKS_HOST, blocksHost))
        put(CensorAnalyzedProperty.BLOCKS_RESPONSE, IntegerResult(CensorAnalyzedProperty.BLOCKS_RESPONSE, blocksResponse))
    }
}