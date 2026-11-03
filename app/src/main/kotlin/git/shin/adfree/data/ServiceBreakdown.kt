package git.shin.adfree.data

import git.shin.adfree.core.DomainUsage
import git.shin.adfree.model.ServiceUsage

/**
 * The services breakdown's rows, built away from the screen so the fallback is
 * testable: a domain the services table does not know is shown by name, and the
 * section only calls itself a list of services while at least one row carries a
 * company.
 */
fun serviceRows(core: List<DomainUsage>): List<ServiceUsage> =
    core.map { row ->
        ServiceUsage(
            domain = row.domain,
            company = row.company,
            category = row.category,
            blocked = row.blocked.toInt(),
            requests = row.requests.toInt(),
            bytesSaved = row.bytesSaved.toLong(),
        )
    }

/** The line under the label: the domain, then what kind of service it is. */
fun serviceSubtitle(row: ServiceUsage): String =
    if (row.category.isBlank()) row.domain else "${row.domain} · ${row.category}"

/** The core already returns the window's groups biggest-first; no resort. */
fun servicesKnownByCompany(rows: List<ServiceUsage>): Boolean = rows.any { it.company.isNotBlank() }
