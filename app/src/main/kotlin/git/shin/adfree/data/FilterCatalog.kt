package git.shin.adfree.data

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
 * * [CatalogFilter.defaultEnabled] is what "Khôi phục mặc định" restores.
 */
enum class FilterGroup(val id: String, val title: String, val subtitle: String) {
    ADS("ads", "Chặn quảng cáo và popup", "Loại bỏ quảng cáo trên web và trong ứng dụng"),
    PRIVACY("privacy", "Riêng tư", "Chặn trình theo dõi và phân tích hành vi"),
    SOCIAL("social", "Tiện ích xã hội", "Ẩn nút Like, chia sẻ và widget mạng xã hội"),
    ANNOYANCES("annoyances", "Làm phiền", "Chặn popup, thông báo cookie và banner"),
    SECURITY("security", "Bảo mật", "Chặn mã độc, lừa đảo và trang nguy hiểm"),
    OTHER("other", "Khác", "Bộ lọc bổ sung và thử nghiệm"),
    LANGUAGE("language", "Ngôn ngữ cụ thể", "Bộ lọc theo khu vực và ngôn ngữ");

    companion object {
        fun fromId(id: String): FilterGroup? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Which engine module flag (R30) gates a category group at request time:
 * the ads module covers the AD and ANNOYANCE categories, the tracking
 * module covers TRACKER, ANALYTICS and SOCIAL. Malware, custom rules and
 * the user rules (`null` gates) are never switched off by a module.
 */
enum class ModuleGate(val title: String) {
    AD_BLOCKING("Chặn quảng cáo"),
    TRACKING("Chặn trình theo dõi"),
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
    val description: String,
    val group: FilterGroup,
    val url: String,
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
            description = "Bộ lọc quảng cáo chính của AdGuard (EasyList + bộ lọc riêng).",
            group = FilterGroup.ADS,
            url = ADGUARD_URL + "2_optimized.txt",
            homepage = "https://adguard.com",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "ag-mobile-ads",
            name = "AdGuard Mobile Ads filter",
            description = "Chặn quảng cáo hiển thị trong ứng dụng di động.",
            group = FilterGroup.ADS,
            url = ADGUARD_URL + "11_optimized.txt",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "easylist",
            name = "EasyList",
            description = "Danh sách quảng cáo quốc tế phổ biến nhất, chuẩn EasyList.",
            group = FilterGroup.ADS,
            url = "https://easylist.to/easylist/easylist.txt",
            homepage = "https://easylist.to/",
        ),

        // --------------------------------------------------------- privacy
        CatalogFilter(
            id = "ag-tracking",
            name = "AdGuard Tracking Protection filter",
            description = "Chặn mã theo dõi và phân tích hành vi trên web.",
            group = FilterGroup.PRIVACY,
            url = ADGUARD_URL + "3_optimized.txt",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "easyprivacy",
            name = "EasyPrivacy",
            description = "Danh sách chống theo dõi phổ biến nhất.",
            group = FilterGroup.PRIVACY,
            url = "https://easylist.to/easylist/easyprivacy.txt",
            homepage = "https://easylist.to/",
        ),
        CatalogFilter(
            id = "peter-lowe",
            name = "Peter Lowe's Blocklist",
            description = "Chặn máy chủ quảng cáo và theo dõi quy mô lớn.",
            group = FilterGroup.PRIVACY,
            url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext",
            homepage = "https://pgl.yoyo.org/adservers/",
        ),
        CatalogFilter(
            id = "ag-url-tracking",
            name = "AdGuard URL Tracking filter",
            description = "Loại bỏ tham số theo dõi (utm, fbclid…) khỏi đường dẫn.",
            group = FilterGroup.PRIVACY,
            url = ADGUARD_URL + "17_optimized.txt",
        ),

        // ---------------------------------------------------------- social
        CatalogFilter(
            id = "ag-social",
            name = "AdGuard Social Media filter",
            description = "Ẩn nút chia sẻ và widget mạng xã hội.",
            group = FilterGroup.SOCIAL,
            url = ADGUARD_URL + "4_optimized.txt",
        ),
        CatalogFilter(
            id = "fanboy-social",
            name = "Fanboy's Social Blocking List",
            description = "Ẩn thành phần mạng xã hội nhúng trong trang.",
            group = FilterGroup.SOCIAL,
            url = "https://secure.fanboy.co.nz/fanboy-social.txt",
        ),

        // ------------------------------------------------------ annoyances
        CatalogFilter(
            id = "ag-cookie",
            name = "AdGuard Cookie Notices filter",
            description = "Ẩn thông báo xin chấp thuận cookie.",
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "18_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-popups",
            name = "AdGuard Popups filter",
            description = "Chặn cửa sổ popup trên trang web.",
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "19_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-app-banners",
            name = "AdGuard Mobile App Banners filter",
            description = "Ẩn banner mời cài ứng dụng di động.",
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "20_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-other-annoy",
            name = "AdGuard Other Annoyances filter",
            description = "Các phần tử gây phiền khác: thanh nổi, nhắc nhở…",
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "21_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-widgets",
            name = "AdGuard Widgets filter",
            description = "Ẩn widget và phần tử nhúng lặt vặt.",
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "22_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-annoyances",
            name = "AdGuard Annoyances filter",
            description = "Tổng hợp mọi loại phiền toái (cookie, popup, widget).",
            group = FilterGroup.ANNOYANCES,
            url = ADGUARD_URL + "14_optimized.txt",
        ),
        CatalogFilter(
            id = "fanboy-annoy",
            name = "Fanboy's Annoyance List",
            description = "Popup, cookie, tự khuyến mãi và phiền toái chung.",
            group = FilterGroup.ANNOYANCES,
            url = "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
        ),
        CatalogFilter(
            id = "easylist-cookie",
            name = "EasyList Cookie List",
            description = "Chặn thông báo cookie theo chuẩn EasyList.",
            group = FilterGroup.ANNOYANCES,
            url = "https://secure.fanboy.co.nz/easylist-cookie.txt",
        ),

        // -------------------------------------------------------- security
        CatalogFilter(
            id = "urlhaus",
            name = "Online Malicious URL Blocklist",
            description = "Danh sách URL phát tán mã độc (URLhaus).",
            group = FilterGroup.SECURITY,
            url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
        ),
        CatalogFilter(
            id = "phishing",
            name = "Phishing URL Blocklist",
            description = "Chặn trang lừa đảo trực tuyến.",
            group = FilterGroup.SECURITY,
            url = "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
        ),
        CatalogFilter(
            id = "scamblock",
            name = "Scam Blocklist",
            description = "Chặn trang lừa đảo và cờ bạc trá hình.",
            group = FilterGroup.SECURITY,
            url = "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
        ),
        CatalogFilter(
            id = "badware",
            name = "uBlock Origin – Badware risks",
            description = "Cảnh báo phần mềm độc hại và rủi ro tải xuống.",
            group = FilterGroup.SECURITY,
            url = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
        ),

        // ----------------------------------------------------------- other
        CatalogFilter(
            id = "ag-dns",
            name = "AdGuard DNS filter",
            description = "Bộ lọc DNS chính thức của AdGuard, nhẹ và toàn diện.",
            group = FilterGroup.OTHER,
            url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            listId = "builtin_dns",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "oisd",
            name = "OISD Big",
            description = "Kho domain quảng cáo và tracking lớn nhất (định dạng hosts).",
            group = FilterGroup.OTHER,
            url = "https://big.oisd.nl/dnsmasq2",
            format = CatalogFilter.FORMAT_HOSTS,
            listId = "builtin_oisd",
            defaultEnabled = true,
        ),
        CatalogFilter(
            id = "stevenblack",
            name = "StevenBlack Unified Hosts",
            description = "Hosts tổng hợp quảng cáo, tracking và mã độc.",
            group = FilterGroup.OTHER,
            url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            format = CatalogFilter.FORMAT_HOSTS,
            listId = "builtin_stevenblack",
        ),
        CatalogFilter(
            id = "hagezi",
            name = "HaGeZi Multi PRO",
            description = "Bộ lọc DNS đa năng, chuyên sâu về quảng cáo và mã độc.",
            group = FilterGroup.OTHER,
            url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        ),
        CatalogFilter(
            id = "ag-experimental",
            name = "AdGuard Experimental filter",
            description = "Bộ lọc thử nghiệm của AdGuard, có thể gây lỗi trang.",
            group = FilterGroup.OTHER,
            url = ADGUARD_URL + "5_optimized.txt",
        ),

        // -------------------------------------------------------- language
        CatalogFilter(
            id = "ag-russian",
            name = "AdGuard Russian filter",
            description = "Bộ lọc cho trang web tiếng Nga.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "1_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-german",
            name = "AdGuard German filter",
            description = "Bộ lọc cho trang web tiếng Đức.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "6_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-japanese",
            name = "AdGuard Japanese filter",
            description = "Bộ lọc cho trang web tiếng Nhật.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "7_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-dutch",
            name = "AdGuard Dutch filter",
            description = "Bộ lọc cho trang web tiếng Hà Lan.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "8_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-spanish",
            name = "AdGuard Spanish/Portuguese filter",
            description = "Bộ lọc cho trang web tiếng Tây Ban Nha và Bồ Đào Nha.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "9_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-turkish",
            name = "AdGuard Turkish filter",
            description = "Bộ lọc cho trang web tiếng Thổ Nhĩ Kỳ.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "13_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-french",
            name = "AdGuard French filter",
            description = "Bộ lọc cho trang web tiếng Pháp.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "16_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-ukrainian",
            name = "AdGuard Ukrainian filter",
            description = "Bộ lọc cho trang web tiếng Ukraina.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "23_optimized.txt",
        ),
        CatalogFilter(
            id = "ag-chinese",
            name = "AdGuard Chinese filter",
            description = "Bộ lọc cho trang web tiếng Trung.",
            group = FilterGroup.LANGUAGE,
            url = ADGUARD_URL + "224_optimized.txt",
        ),
        CatalogFilter(
            id = "polish",
            name = "Polish filters for AdBlock/uBlock/AdGuard",
            description = "Bộ lọc Ba Lan chính thức (MajkiIT).",
            group = FilterGroup.LANGUAGE,
            url = "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt",
        ),
        CatalogFilter(
            id = "hostsvn",
            name = "hostsVN",
            description = "Chặn quảng cáo Việt Nam (định dạng hosts).",
            group = FilterGroup.LANGUAGE,
            url = "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
            format = CatalogFilter.FORMAT_HOSTS,
        ),
        CatalogFilter(
            id = "abpvn",
            name = "ABPVN List",
            description = "Bộ lọc quảng cáo tiếng Việt cho AdGuard/uBlock.",
            group = FilterGroup.LANGUAGE,
            url = "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_adguard.txt",
        ),
    )

    fun byId(id: String): CatalogFilter? = filters.firstOrNull { it.id == id }
}

/** One userscript offered in the Extensions section. */
data class CatalogUserScript(
    val id: String,
    val name: String,
    val description: String,
    val url: String,
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
            description = "Giữ các thư viện dò chặn quảng cáo (BlockAdBlock, FuckAdBlock) khỏi thấy dấu vết ẩn quảng cáo.",
            url = "",
            builtin = true,
        ),
        CatalogUserScript(
            id = "adguard-extra",
            name = "AdGuard Extra",
            description = "Tăng cường chặn quảng cáo trên trang phức tạp (thử nghiệm, có thể làm chậm trang).",
            url = "https://userscripts.adtidy.org/release/adguard-extra/1.0/adguard-extra.user.js",
        ),
        CatalogUserScript(
            id = "disable-amp",
            name = "Chặn trang AMP",
            description = "Chuyển trang AMP của Google về trang gốc.",
            url = "https://userscripts.adtidy.org/release/disable-amp/1.0/disable-amp.user.js",
        ),
    )
}
