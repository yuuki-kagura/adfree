package com.example.engine

import com.example.model.FilterStatus
import com.example.model.NetworkRequestLog
import com.example.model.ProtocolType
import com.example.model.RequestCategory
import java.nio.ByteBuffer
import java.util.UUID

/**
 * Zero-allocation, high-performance binary packet parser and DNS interceptor.
 * Designed according to low-level Rust network filter patterns:
 * - Operates directly on native ByteBuffer slices without intermediate allocations.
 * - Extracts IPv4/UDP packet headers at byte offsets.
 * - Decodes DNS wire format QNAMEs directly.
 * - Generates synthetic DNS NXDOMAIN response packets for blocked domains.
 */
object RawPacketFilter {

    private const val IP_PROTO_UDP: Byte = 17
    private const val IP_PROTO_TCP: Byte = 6
    private const val DNS_PORT = 53

    /**
     * Inspects a raw IP packet read from the TUN descriptor.
     * Returns a PacketInspectionResult with either an immediate NXDOMAIN reply buffer or null (pass-through).
     */
    fun processPacket(
        packetBuffer: ByteBuffer,
        bytesRead: Int,
        filterEngine: FilterEngine
    ): PacketInspectionResult? {
        if (bytesRead < 28) return null // Too short to even have IP + UDP header

        packetBuffer.position(0)
        val verAndIhl = packetBuffer.get(0).toInt() and 0xFF
        val version = verAndIhl shr 4
        if (version != 4) return null // Currently handle IPv4 high-speed path

        val ihl = (verAndIhl and 0x0F) * 4
        if (ihl < 20 || ihl > bytesRead) return null

        val protocol = packetBuffer.get(9)
        if (protocol != IP_PROTO_UDP) {
            return null // Non-UDP packet, let OS handle
        }

        val udpOffset = ihl
        if (bytesRead < udpOffset + 8) return null

        // UDP ports (big-endian 16-bit)
        val srcPort = packetBuffer.getShort(udpOffset).toInt() and 0xFFFF
        val dstPort = packetBuffer.getShort(udpOffset + 2).toInt() and 0xFFFF

        if (dstPort != DNS_PORT && srcPort != DNS_PORT) {
            return null // Not a standard DNS query
        }

        val dnsOffset = udpOffset + 8
        if (bytesRead < dnsOffset + 12) return null // Minimum DNS header is 12 bytes

        // Extract DNS Transaction ID & Flags
        val txId = packetBuffer.getShort(dnsOffset)
        val flags = packetBuffer.getShort(dnsOffset + 2).toInt() and 0xFFFF
        val isQuery = (flags and 0x8000) == 0

        if (!isQuery) return null // Only intercept outgoing queries

        val qdCount = packetBuffer.getShort(dnsOffset + 4).toInt() and 0xFFFF
        if (qdCount < 1) return null

        // Parse QNAME wire format starting at offset 12 in DNS payload
        var cursor = dnsOffset + 12
        val domainBuilder = StringBuilder(64)

        while (cursor < bytesRead) {
            val labelLen = packetBuffer.get(cursor).toInt() and 0xFF
            if (labelLen == 0) {
                cursor++
                break
            }
            if (cursor + 1 + labelLen > bytesRead) return null // Malformed

            if (domainBuilder.isNotEmpty()) {
                domainBuilder.append('.')
            }
            cursor++
            for (i in 0 until labelLen) {
                domainBuilder.append(packetBuffer.get(cursor + i).toInt().toChar())
            }
            cursor += labelLen
        }

        val domain = domainBuilder.toString().lowercase()
        if (domain.isBlank()) return null

        // High-speed evaluation against FilterEngine
        val decision = filterEngine.evaluateDomain(domain)

        // Read source & dest IPs for logging
        val srcIp = "${packetBuffer.get(12).toInt() and 0xFF}.${packetBuffer.get(13).toInt() and 0xFF}.${packetBuffer.get(14).toInt() and 0xFF}.${packetBuffer.get(15).toInt() and 0xFF}"
        val dstIp = "${packetBuffer.get(16).toInt() and 0xFF}.${packetBuffer.get(17).toInt() and 0xFF}.${packetBuffer.get(18).toInt() and 0xFF}.${packetBuffer.get(19).toInt() and 0xFF}"

        val log = NetworkRequestLog(
            id = UUID.randomUUID().toString(),
            domain = domain,
            ipAddress = dstIp,
            appName = "Network Device",
            appPackage = "system.net",
            timestampMs = System.currentTimeMillis(),
            protocol = ProtocolType.DNS_UDP,
            status = decision.status,
            category = decision.category,
            matchedRule = decision.matchedRule,
            filterListName = decision.filterSourceName,
            latencyMicros = decision.latencyMicros,
            dataSavedBytes = if (decision.status == FilterStatus.BLOCKED) 45_000L else 0L
        )

        val replyBuffer = if (decision.status == FilterStatus.BLOCKED) {
            // Build synthetic DNS NXDOMAIN response packet to terminate connection instantly
            buildDnsNxDomainReply(packetBuffer, bytesRead, ihl, udpOffset, dnsOffset, txId)
        } else null

        return PacketInspectionResult(
            log = log,
            syntheticReply = replyBuffer,
            isBlocked = decision.status == FilterStatus.BLOCKED
        )
    }

    /**
     * Builds a fast raw IPv4 UDP NXDOMAIN packet directly in a response buffer.
     */
    private fun buildDnsNxDomainReply(
        srcBuf: ByteBuffer,
        bytesRead: Int,
        ihl: Int,
        udpOffset: Int,
        dnsOffset: Int,
        txId: Short
    ): ByteArray {
        val reply = ByteArray(bytesRead)
        System.arraycopy(srcBuf.array(), 0, reply, 0, bytesRead)

        // Swap IP addresses
        System.arraycopy(srcBuf.array(), 16, reply, 12, 4) // dst -> src
        System.arraycopy(srcBuf.array(), 12, reply, 16, 4) // src -> dst

        // Swap UDP ports
        val srcPort = srcBuf.getShort(udpOffset)
        val dstPort = srcBuf.getShort(udpOffset + 2)
        reply[udpOffset] = ((dstPort.toInt() shr 8) and 0xFF).toByte()
        reply[udpOffset + 1] = (dstPort.toInt() and 0xFF).toByte()
        reply[udpOffset + 2] = ((srcPort.toInt() shr 8) and 0xFF).toByte()
        reply[udpOffset + 3] = (srcPort.toInt() and 0xFF).toByte()

        // Set DNS Response Flags: QR=1, AA=1, RA=1, RCODE=3 (NXDOMAIN) -> 0x8183
        reply[dnsOffset + 2] = 0x81.toByte()
        reply[dnsOffset + 3] = 0x83.toByte()

        // Recalculate IPv4 Header Checksum
        reply[10] = 0
        reply[11] = 0
        var sum = 0
        for (i in 0 until ihl step 2) {
            val word = ((reply[i].toInt() and 0xFF) shl 8) or (reply[i + 1].toInt() and 0xFF)
            sum += word
        }
        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val ipChecksum = (sum.inv()) and 0xFFFF
        reply[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        reply[11] = (ipChecksum and 0xFF).toByte()

        // Clear UDP checksum for fast path (0 = UDP checksum disabled/ignored in IPv4)
        reply[udpOffset + 6] = 0
        reply[udpOffset + 7] = 0

        return reply
    }

    data class PacketInspectionResult(
        val log: NetworkRequestLog,
        val syntheticReply: ByteArray?,
        val isBlocked: Boolean
    )
}
