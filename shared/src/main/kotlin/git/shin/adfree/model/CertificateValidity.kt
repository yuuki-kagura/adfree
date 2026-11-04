package git.shin.adfree.model

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Expiry of the local CA, read from the PEM the core hands to Settings.
 *
 * The certificate is the one thing the HTTPS feature asks the user to install
 * outside the app; nothing else warns them when it lapses and every TLS
 * connection starts failing. `null` means the PEM could not be parsed, not
 * that the certificate is fine.
 */
fun caNotAfterMs(pem: String): Long? {
    if (pem.isBlank()) return null
    return runCatching {
        val factory = CertificateFactory.getInstance("X.509")
        val cert = factory.generateCertificate(
            ByteArrayInputStream(pem.toByteArray()),
        ) as X509Certificate
        cert.notAfter.time
    }.getOrNull()
}
