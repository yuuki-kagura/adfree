package git.shin.adfree.data

import git.shin.adfree.platform.KeyValueStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * What the Settings screen shows and the receiver checks: whether broadcasts
 * from other apps are honoured at all, and the secret they have to carry.
 */
data class AutomationControl(
    val enabled: Boolean = false,
    val token: String = "",
)

/**
 * The gate for external automation (Tasker's "Send Intent").
 *
 * Deliberately outside `ProtectionState`: the token is a device-local secret,
 * and a settings record is exported verbatim into the JSON backup the user can
 * hand to anyone. A backup that carried it would put control of protection in
 * any file the user has shared.
 */
class AutomationGate(private val store: KeyValueStore) {

    private val _state = MutableStateFlow(read())
    val state: StateFlow<AutomationControl> = _state.asStateFlow()

    fun setEnabled(enabled: Boolean) {
        store.putBoolean(KEY_ENABLED, enabled)
        _state.value = read()
    }

    /**
     * Issues a fresh token and returns it. The old one stops working at the
     * same moment, so a leaked value can be retired without uninstalling.
     */
    fun rotateToken(): String {
        val fresh = newToken()
        store.putString(KEY_TOKEN, fresh)
        store.putBoolean(KEY_ENABLED, false)
        _state.value = read()
        return fresh
    }

    /**
     * True when [presented] authorises one broadcast. Off by default, so a
     * freshly installed app obeys nothing; the comparison is constant time and
     * an unset token never matches, so a missing extra cannot slip through.
     */
    fun authorize(presented: String?): Boolean {
        val current = _state.value
        if (!current.enabled || current.token.isEmpty() || presented.isNullOrEmpty()) return false
        return MessageDigest.isEqual(
            current.token.toByteArray(),
            presented.toByteArray(),
        )
    }

    private fun read(): AutomationControl {
        val stored = store.getString(KEY_TOKEN) ?: run {
            // Generated once, on the device, and never shown anywhere but the
            // Settings row the user reads it from.
            val fresh = newToken()
            store.putString(KEY_TOKEN, fresh)
            fresh
        }
        return AutomationControl(
            enabled = store.getBoolean(KEY_ENABLED, false),
            token = stored,
        )
    }

    private companion object {
        const val KEY_ENABLED = "allow_external_control"
        const val KEY_TOKEN = "control_token"

        /** 128 bits, hex: long enough that guessing is not a strategy. */
        fun newToken(): String {
            val bytes = ByteArray(16)
            SecureRandom().nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }
    }
}
