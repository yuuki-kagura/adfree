package git.shin.adfree.data

import androidx.annotation.StringRes
import git.shin.adfree.R

/**
 * The bundled catalogue of filter lists behind the "Bộ lọc" tab.
 *
 * The shape mirrors the catalogue AdGuard ships in `assets/preset/filters.json`
 * (group, update URL, one-line description), but the list is curated: forty
 * lists people actually use beat eighty that mostly stay off. AdGuard's own
 * `_optimized` builds are used where they exist because that is what their
 * Android client downloads too.
 *
 * Conventions:
 * * [CatalogFilter.format] is `standard` (AdGuard/EasyList syntax) or `hosts`;
 * * [CatalogFilter.listId] lets an entry reuse a file older builds already
 *   downloaded (`builtin_dns`, `builtin_oisd`, `builtin_stevenblack`);
 * * [CatalogFilter.defaultEnabled] is what "Khôi phục mặc định" restores;
 * * display text lives in `strings.xml`; [CatalogFilter.name] is the stable
 *   brand name used in downloads and diagnostics.
 */
enum class FilterGroup(
    val id: String,
    @StringRes val titleRes: Int,
    @StringRes val subtitleRes: Int,
) {
    ADS("ads", R.string.filter_group_ads_title, R.string.filter_group_ads_subtitle),
    PRIVACY("privacy", R.string.filter_group_privacy_title, R.string.filter_group_privacy_subtitle),
    SOCIAL("social", R.string.filter_group_social_title, R.string.filter_group_social_subtitle),
    ANNOYANCES(
        "annoyances",
        R.string.filter_group_annoyances_title,
        R.string.filter_group_annoyances_subtitle,
    ),
    SECURITY("security", R.string.filter_group_security_title, R.string.filter_group_security_subtitle),
    OTHER("other", R.string.filter_group_other_title, R.string.filter_group_other_subtitle),
    LANGUAGE("language", R.string.filter_group_language_title, R.string.filter_group_language_subtitle);

    companion object {
        fun fromId(id: String): FilterGroup? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Which engine module flag gates a category group at request time:
 * the ads module covers the AD and ANNOYANCE categories, the tracking
 * module covers TRACKER, ANALYTICS and SOCIAL. Malware, custom rules and
 * the user rules (`null` gates) are never switched off by a module.
 */
enum class ModuleGate(@StringRes val titleRes: Int) {
    AD_BLOCKING(R.string.filter_gate_ad_blocking),
    TRACKING(R.string.filter_gate_tracking),
}

val FilterGroup.moduleGate: ModuleGate?
    get() = when (this) {
        FilterGroup.ADS, FilterGroup.ANNOYANCES, FilterGroup.LANGUAGE -> ModuleGate.AD_BLOCKING
        FilterGroup.PRIVACY, FilterGroup.SOCIAL -> ModuleGate.TRACKING
        else -> null
    }

data class CatalogFilter(
    val id: String,
    val name: String,
    @StringRes val descriptionRes: Int,
    val group: FilterGroup,
    val url: String,
    /** Non-zero when the row shows a localized name instead of [name]. */
    @StringRes val nameRes: Int = 0,
    val format: String = FORMAT_STANDARD,
    val homepage: String? = null,
    val defaultEnabled: Boolean = false,
    val listId: String? = null,
) {
    companion object {
        const val FORMAT_STANDARD = "standard"
        const val FORMAT_HOSTS = "hosts"
    }
}

object FilterCatalog {

    private const val ADGUARD_URL = "https://filters.adtidy.org/android/filters/"

    val filters: List<CatalogFilter> = listOf(
        // ------------------------------------------------------------- ads
        CatalogFilter(
            id = "ag-base",
            name = "AdGuard Base filter",
            descriptionRes = R.string.filter_desc_ag_base,
            group = FilterGroup.ADS,
            url = ADGUARD_URL + "2_optimized.txt",
            homepage = "https://adguard.com",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "ag-mobile-ads",
            name = "AdGuard Mobile Ads filter",
            descriptionRes = R.string.filter_desc_ag_mobile_ads,
            group = FilterGroup.ADS,
            url = ADGUARD_URL + "11_optimized.txt",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "easylist",
            name = "EasyList",
            descriptionRes = R.string.filter_desc_easylist,
            group = FilterGroup.ADS,
            url = "https://easylist.to/easylist/easylist.txt",
            homepage = "https://easylist.to/",
        ),

        // --------------------------------------------------------- privacy
        CatalogFilter(
            id = "ag-tracking",
            name = "AdGuard Tracking Protection filter",
            descriptionRes = R.string.filter_desc_ag_tracking,
            group = FilterGroup.PRIVACY,
            url = ADGUARD_URL + "3_optimized.txt",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "easyprivacy",
            name = "EasyPrivacy",
            descriptionRes = R.string.filter_desc_easyprivacy,
            group = FilterGroup.PRIVACY,
            url = "https://easylist.to/easylist/easyprivacy.txt",
            homepage = "https://easylist.to/",
        ),
        CatalogFilter(
            id = "peter-lowe",
            name = "Peter Lowe's Blocklist",
            descriptionRes = R.string.filter_desc_peter_lowe,
            group = FilterGroup.PRIVACY,
            url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext",
            homepage = "https://pgl.yoyo.org/adservers/",
        ),
        CatalogFilter(
            id = "ag-url-tracking",
            name = "AdGuard URL Tracking filter",
            descriptionRes = R.string.filter_desc_ag_url_tracking,
            group = FilterGroup.PRIVACY,
            url = ADGUARD_URL + "17_optimized.txt",
        ),

        // ---------------------------------------------------------- social
        CatalogFilter(
            id = "ag-social",
            name = "AdGuard Social Media filter",
            descriptionRes = R.string.filter_desc_ag_social,
            group = FilterGroup.SOCIAL,
            url = ADGUARD_URL + "4_optimized.txt",
        ),
        CatalogFilter(
            id = "fanboy-social",
            name = "Fanboy's Social Blocking List",
            descriptionRes = R.string.filter_desc_fanboy_social,
            group = FilterGroup.SOCIAL,
            url = "https://secure.fanboy.co.nz/fanboy-social.txt",
        ),

        // ------------------------------------------------------ annoyances
        CatalogFilter(
            id = "ag-cookie",
            name = "AdGuard Cookie Notices filter",
            descriptionRes = R.string.filter_desc_ag_cookie,
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "18_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-popups",
            name = "AdGuard Popups filter",
            descriptionRes = R.string.filter_desc_ag_popups,
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "19_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-app-banners",
            name = "AdGuard Mobile App Banners filter",
            descriptionRes = R.string.filter_desc_ag_app_banners,
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "20_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-other-annoy",
            name = "AdGuard Other Annoyances filter",
            descriptionRes = R.string.filter_desc_ag_other_annoy,
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "21_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-widgets",
            name = "AdGuard Widgets filter",
            descriptionRes = R.string.filter_desc_ag_widgets,
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "22_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-annoyances",
            name = "AdGuard Annoyances filter",
            descriptionRes = R.string.filter_desc_ag_annoyances,
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "14_optimized.txt",
        ),
        CatalogFilter(
            id = "fanboy-annoy",
            name = "Fanboy's Annoyance List",
            descriptionRes = R.string.filter_desc_fanboy_annoy,
            group = FilterGroup.ANNOYANCES,
            url = "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
        ),
        CatalogFilter(
            id = "easylist-cookie",
            name = "EasyList Cookie List",
            descriptionRes = R.string.filter_desc_easylist_cookie,
            group = FilterGroup.ANNOYANCES,
            url = "https://secure.fanboy.co.nz/easylist-cookie.txt",
        ),
        CatalogFilter(
            id = "adblock-warning-removal",
            name = "Adblock Warning Removal List",
            descriptionRes = R.string.filter_desc_adblock_warning_removal,
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "207_optimized.txt",
        ),

        // -------------------------------------------------------- security
        CatalogFilter(
            id = "urlhaus",
            name = "Online Malicious URL Blocklist",
            descriptionRes = R.string.filter_desc_urlhaus,
            group = FilterGroup.SECURITY,
            url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
        ),
        CatalogFilter(
            id = "phishing",
            name = "Phishing URL Blocklist",
            descriptionRes = R.string.filter_desc_phishing,
            group = FilterGroup.SECURITY,
            url = "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
        ),
        CatalogFilter(
            id = "scamblock",
            name = "Scam Blocklist",
            descriptionRes = R.string.filter_desc_scamblock,
            group = FilterGroup.SECURITY,
            url = "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
        ),
        CatalogFilter(
            id = "badware",
            name = "uBlock Origin – Badware risks",
            descriptionRes = R.string.filter_desc_badware,
            group = FilterGroup.SECURITY,
            url = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
        ),
        CatalogFilter(
            id = "dandelion-malware",
            name = "Dandelion Sprout's Anti-Malware List",
            descriptionRes = R.string.filter_desc_dandelion_malware,
            group = FilterGroup.SECURITY,
            url = ADGUARD_URL + "259_optimized.txt",
        ),

        // ----------------------------------------------------------- other
        CatalogFilter(
            id = "ag-dns",
            name = "AdGuard DNS filter",
            descriptionRes = R.string.filter_desc_ag_dns,
            group = FilterGroup.OTHER,
            url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            listId = "builtin_dns",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "oisd",
            name = "OISD Big",
            descriptionRes = R.string.filter_desc_oisd,
            group = FilterGroup.OTHER,
            url = "https://big.oisd.nl/dnsmasq2",
            format = CatalogFilter.FORMAT_HOSTS,
            listId = "builtin_oisd",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "stevenblack",
            name = "StevenBlack Unified Hosts",
            descriptionRes = R.string.filter_desc_stevenblack,
            group = FilterGroup.OTHER,
            url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            format = CatalogFilter.FORMAT_HOSTS,
            listId = "builtin_stevenblack",
        ),
        CatalogFilter(
            id = "hagezi",
            name = "HaGeZi Multi PRO",
            descriptionRes = R.string.filter_desc_hagezi,
            group = FilterGroup.OTHER,
            url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        ),
        CatalogFilter(
            id = "ag-experimental",
            name = "AdGuard Experimental filter",
            descriptionRes = R.string.filter_desc_ag_experimental,
            group = FilterGroup.OTHER,
            url = ADGUARD_URL + "5_optimized.txt",
        ),

        // -------------------------------------------------------- language
        CatalogFilter(
            id = "ag-russian",
            name = "AdGuard Russian filter",
            descriptionRes = R.string.filter_desc_ag_russian,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "1_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-german",
            name = "AdGuard German filter",
            descriptionRes = R.string.filter_desc_ag_german,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "6_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-japanese",
            name = "AdGuard Japanese filter",
            descriptionRes = R.string.filter_desc_ag_japanese,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "7_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-dutch",
            name = "AdGuard Dutch filter",
            descriptionRes = R.string.filter_desc_ag_dutch,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "8_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-spanish",
            name = "AdGuard Spanish/Portuguese filter",
            descriptionRes = R.string.filter_desc_ag_spanish,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "9_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-turkish",
            name = "AdGuard Turkish filter",
            descriptionRes = R.string.filter_desc_ag_turkish,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "13_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-french",
            name = "AdGuard French filter",
            descriptionRes = R.string.filter_desc_ag_french,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "16_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-ukrainian",
            name = "AdGuard Ukrainian filter",
            descriptionRes = R.string.filter_desc_ag_ukrainian,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "23_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-chinese",
            name = "AdGuard Chinese filter",
            descriptionRes = R.string.filter_desc_ag_chinese,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "224_optimized.txt",
        ),
        CatalogFilter(
            id = "polish",
            name = "Polish filters for AdBlock/uBlock/AdGuard",
            descriptionRes = R.string.filter_desc_polish,
            group = FilterGroup.LANGUAGE,
            url = "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt",
        ),
        CatalogFilter(
            id = "hostsvn",
            name = "hostsVN",
            descriptionRes = R.string.filter_desc_hostsvn,
            group = FilterGroup.LANGUAGE,
            url = "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
            format = CatalogFilter.FORMAT_HOSTS,
        ),
        CatalogFilter(
            id = "abpvn",
            name = "ABPVN List",
            descriptionRes = R.string.filter_desc_abpvn,
            group = FilterGroup.LANGUAGE,
            url = "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_adguard.txt",
        ),
        // AdGuard's own language filters, same Android `_optimized` bodies the
        // catalogue above uses. Coverage for the languages a Vietnamese user
        // is most likely to browse; all URLs verified against filters.adtidy.org.
        CatalogFilter(
            id = "ag-italian",
            name = "AdGuard Italian filter",
            descriptionRes = R.string.filter_desc_ag_italian,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "26_optimized.txt",
        ),
        CatalogFilter(
            id = "easylist-germany",
            name = "EasyList Germany",
            descriptionRes = R.string.filter_desc_easylist_germany,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "107_optimized.txt",
        ),
        CatalogFilter(
            id = "liste-fr",
            name = "Liste FR",
            descriptionRes = R.string.filter_desc_liste_fr,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "113_optimized.txt",
        ),
        CatalogFilter(
            id = "easylist-spanish",
            name = "EasyList Spanish",
            descriptionRes = R.string.filter_desc_easylist_spanish,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "231_optimized.txt",
        ),
        CatalogFilter(
            id = "easylist-portuguese",
            name = "EasyList Portuguese",
            descriptionRes = R.string.filter_desc_easylist_portuguese,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "124_optimized.txt",
        ),
        CatalogFilter(
            id = "easylist-china",
            name = "EasyList China",
            descriptionRes = R.string.filter_desc_easylist_china,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "104_optimized.txt",
        ),
        CatalogFilter(
            id = "easylist-thailand",
            name = "EasyList Thailand",
            descriptionRes = R.string.filter_desc_easylist_thailand,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "202_optimized.txt",
        ),
        CatalogFilter(
            id = "adblock-id",
            name = "AdBlockID",
            descriptionRes = R.string.filter_desc_adblock_id,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "120_optimized.txt",
        ),
        CatalogFilter(
            id = "youslist",
            name = "YousList",
            descriptionRes = R.string.filter_desc_youslist,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "244_optimized.txt",
        ),
        CatalogFilter(
            id = "indianlist",
            name = "IndianList",
            descriptionRes = R.string.filter_desc_indianlist,
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "253_optimized.txt",
        ),
    )

    fun byId(id: String): CatalogFilter? = filters.firstOrNull { it.id == id }
}

/** One userscript offered in the Extensions section. */
data class CatalogUserScript(
    val id: String,
    val name: String,
    @StringRes val descriptionRes: Int,
    val url: String,
    /** Non-zero when the row shows a localized name instead of [name]. */
    @StringRes val nameRes: Int = 0,
    /**
     * Body shipped with the core instead of downloaded (`coreInstallBuiltinScripts`
     * writes it into the store); such an entry is on by default and has no URL.
     */
    val builtin: Boolean = false,
)

object UserScriptCatalog {
    val scripts: List<CatalogUserScript> = listOf(
        CatalogUserScript(
            id = "adfree-extra",
            name = "AdFree Extra",
            descriptionRes = R.string.script_catalog_adfree_extra,
            url = "",
            builtin = true,
        ),
        CatalogUserScript(
            id = "adguard-extra",
            name = "AdGuard Extra",
            descriptionRes = R.string.script_catalog_adguard_extra,
            url = "https://userscripts.adtidy.org/release/adguard-extra/1.0/adguard-extra.user.js",
        ),
        CatalogUserScript(
            id = "disable-amp",
            name = "AMP page blocker",
            descriptionRes = R.string.script_catalog_disable_amp,
            url = "https://userscripts.adtidy.org/release/disable-amp/1.0/disable-amp.user.js",
            nameRes = R.string.script_name_disable_amp,
        ),
    )
}
