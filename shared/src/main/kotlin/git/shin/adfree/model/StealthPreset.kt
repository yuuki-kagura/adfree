package git.shin.adfree.model

/**
 * The privacy levels AdGuard puts above its stealth switches: one tap writes a
 * documented set of switches instead of asking the user to find twelve.
 *
 * The level is not stored anywhere. It is read back from the switches it would
 * have written, so the radio cannot claim a level the traffic is not getting —
 * a stored level would go stale the moment a restore, a backup from another
 * device, or an older build wrote one switch differently.
 */
enum class StealthPreset {
    /** What a fresh install already uses: nothing new breaks. */
    STANDARD,

    /** Standard plus the edits a site has no legitimate use for. */
    HIGH,

    /** Every switch, including the ones that cost logins and caching. */
    ULTRA,

    /** A combination no level writes; the user assembled it by hand. */
    CUSTOM,
    ;

    /**
     * The switches this level stands for. A set is a promise rather than an
     * addition: a switch the level does not name is turned off, so picking a
     * level also says what stops happening.
     */
    fun applyTo(settings: ProtectionSettings): ProtectionSettings {
        val writes = writes() ?: return settings
        return settings.copy(
            isStealthModeEnabled = true,
            stripUtmTracking = writes.stripUtm,
            blockWebRtcLeaks = writes.blockWebRtc,
            disguiseUserAgent = writes.disguiseUserAgent,
            blockThirdPartyCookies = writes.blockThirdPartyCookies,
            blockAllCookies = writes.blockAllCookies,
            stripEtag = writes.stripEtag,
            stripThirdPartyAuthorization = writes.stripThirdPartyAuthorization,
            hideThirdPartyReferer = writes.hideThirdPartyReferer,
            injectGpcDnt = writes.injectGpcDnt,
            hideSearchQuery = writes.hideSearchQuery,
            blockPushApi = writes.blockPushApi,
            blockGeolocationApi = writes.blockGeolocationApi,
        )
    }

    /** The set this level writes; `null` for [CUSTOM], which writes nothing. */
    private fun writes(): Switches? = when (this) {
        STANDARD -> Switches(
            stripUtm = true,
            blockThirdPartyCookies = true,
        )
        HIGH -> Switches(
            stripUtm = true,
            blockWebRtc = true,
            blockThirdPartyCookies = true,
            hideThirdPartyReferer = true,
            injectGpcDnt = true,
            hideSearchQuery = true,
        )
        ULTRA -> Switches(
            stripUtm = true,
            blockWebRtc = true,
            disguiseUserAgent = true,
            blockThirdPartyCookies = true,
            blockAllCookies = true,
            stripEtag = true,
            stripThirdPartyAuthorization = true,
            hideThirdPartyReferer = true,
            injectGpcDnt = true,
            hideSearchQuery = true,
            blockPushApi = true,
            blockGeolocationApi = true,
        )
        CUSTOM -> null
    }

    companion object {
        /** The level whose set the current switches match, else [CUSTOM]. */
        fun of(settings: ProtectionSettings): StealthPreset {
            val now = Switches(
                stripUtm = settings.stripUtmTracking,
                blockWebRtc = settings.blockWebRtcLeaks,
                disguiseUserAgent = settings.disguiseUserAgent,
                blockThirdPartyCookies = settings.blockThirdPartyCookies,
                blockAllCookies = settings.blockAllCookies,
                stripEtag = settings.stripEtag,
                stripThirdPartyAuthorization = settings.stripThirdPartyAuthorization,
                hideThirdPartyReferer = settings.hideThirdPartyReferer,
                injectGpcDnt = settings.injectGpcDnt,
                hideSearchQuery = settings.hideSearchQuery,
                blockPushApi = settings.blockPushApi,
                blockGeolocationApi = settings.blockGeolocationApi,
            )
            return entries.firstOrNull { it.writes() == now } ?: CUSTOM
        }
    }
}

/**
 * The twelve stealth switches as one comparable value. Only the ones a level
 * names are mentioned by the callers; the rest default to off.
 *
 * Anti-DPI and the masked address are deliberately absent: a level promises what
 * a site sees, and splitting the handshake changes only what a middlebox sees
 * while the mask is text the user typed, so both stay rows of their own and
 * survive whichever level is picked.
 */
private data class Switches(
    val stripUtm: Boolean = false,
    val blockWebRtc: Boolean = false,
    val disguiseUserAgent: Boolean = false,
    val blockThirdPartyCookies: Boolean = false,
    val blockAllCookies: Boolean = false,
    val stripEtag: Boolean = false,
    val stripThirdPartyAuthorization: Boolean = false,
    val hideThirdPartyReferer: Boolean = false,
    val injectGpcDnt: Boolean = false,
    val hideSearchQuery: Boolean = false,
    val blockPushApi: Boolean = false,
    val blockGeolocationApi: Boolean = false,
)
