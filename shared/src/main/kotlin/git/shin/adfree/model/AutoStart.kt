package git.shin.adfree.model

/**
 * Whether a boot broadcast should bring the tunnel back.
 *
 * Both switches are required: the user opted into start-on-boot, and
 * protection was actually on when the device shut down. VPN consent is checked
 * later by [git.shin.adfree.vpn.VpnController], which can only ask the system.
 */
fun shouldStartOnBoot(autoStart: Boolean, protectionWasOn: Boolean): Boolean =
    autoStart && protectionWasOn
