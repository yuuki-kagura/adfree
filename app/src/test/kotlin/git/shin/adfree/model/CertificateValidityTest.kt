package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Calendar
import java.util.GregorianCalendar
import java.util.TimeZone

class CertificateValidityTest {

    /** Self-signed CA generated for this test only, valid until 2036-10-19. */
    private val pem = """
        -----BEGIN CERTIFICATE-----
        MIIDEzCCAfugAwIBAgIUXmPLaT1yB4CjAsQMyuahXGTbloYwDQYJKoZIhvcNAQEL
        BQAwGTEXMBUGA1UEAwwOQWRGcmVlIFRlc3QgQ0EwHhcNMjYxMDIyMTAzMzM0WhcN
        MzYxMDE5MTAzMzM0WjAZMRcwFQYDVQQDDA5BZEZyZWUgVGVzdCBDQTCCASIwDQYJ
        KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQ8KCioTypUTRDbxQc/qtYU+08FN4TS
        ed7sIprLZ9tWWTO3P2/OrblfYBvhWd6RCakcusoc/cwGvhZYoWxtu/guOHAlpJgt
        mom/awOTgilMAkUlyCd1a7fkbU+TRQJR4pu/ssf1OwTo+Jgq2eaGkaErhkcAtiji
        sZM7VxIW9JXndnjenTJQTSQVqg0JGHe52vJp9cxkWba+O2yTdcopqKk6xzDsGrPE
        0HzE+4kxnFZN7Y+BHG8b4kOp0Fq8Mk7+fA+Ptj8n2ox81cyQYIdPihqQItVTBP5q
        vz0aU1zgl4odI+wS2odH99HdaVRVdjCFiZdoFAqdQ99G8WZTXe1z5I0CAwEAAaNT
        MFEwHQYDVR0OBBYEFHfPbAQU4r0doJTVunbRH8dVHLRrMB8GA1UdIwQYMBaAFHfP
        bAQU4r0doJTVunbRH8dVHLRrMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
        BQADggEBAETkP8dSXjNDkWRlrmP4wwd41TxbRXm7rlAUOYil4XpwBwJ71O+6og5Z
        pKPbK5VKwPkL0k8rh3DtUE6OLMjqg94ALc8IwaOt9TmZ2l9HaFPn1ubXI+vuRylc
        aL2aa1pMK91mtMOtLzzmGKnMemOnwFBVRYumeZlr/rDEKrl41ar10/Q6uB3+M7sH
        Jxh8h19PkFBMIJyiQJJXH3tNrwSzqxLnzc0oGJFKX8pSiJCYtlZmaysEbku5t3xZ
        oem8LINtBBgHgeuEaHJHqYOzVSWaGhDFeFjyflrd1hwIGTW81a1lkToPj8zdkgvL
        +sHlK+i1AIF6Otsp72xoDrhj/Jth7Qc=
        -----END CERTIFICATE-----
    """.trimIndent()

    @Test
    fun readsTheNotAfterDate() {
        val expiry = caNotAfterMs(pem)!!
        val calendar = GregorianCalendar(TimeZone.getTimeZone("GMT"))
        calendar.timeInMillis = expiry
        assertEquals(2036, calendar.get(Calendar.YEAR))
        assertEquals(Calendar.OCTOBER, calendar.get(Calendar.MONTH))
        assertEquals(19, calendar.get(Calendar.DAY_OF_MONTH))
    }

    @Test
    fun unparseableInputHasNoExpiry() {
        assertNull(caNotAfterMs(""))
        assertNull(caNotAfterMs("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"))
    }
}
