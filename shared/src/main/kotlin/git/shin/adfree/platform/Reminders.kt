package git.shin.adfree.platform

import git.shin.adfree.model.AppLanguage

/**
 * The notification and scheduling side effects the repository raises. Android
 * posts real notifications and WorkManager jobs; the desktop host ignores them.
 */
interface Reminders {

    fun syncHttpsReminder(language: AppLanguage, protectionActive: Boolean, caTrusted: Boolean)

    fun notifyFirewall(language: AppLanguage, packageName: String, appName: String)

    fun notifySecurity(language: AppLanguage, domain: String, listName: String?)

    fun scheduleFilterUpdates(hours: Int)
}
