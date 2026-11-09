package git.shin.adfree.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.ui.theme.UiSize
import git.shin.adfree.ui.theme.isDesktopLayout

/**
 * The pieces AdGuard for Windows builds its pages from: one page title, flat
 * rows on the bare surface, hairlines between them, and section labels that
 * name a group instead of boxing it in a card.
 *
 * Every one of these has a phone shape too — a taller row, a wider gap — so a
 * screen can adopt the desktop body without losing its Android one.
 */

/** Page title, optional one-line subtitle, actions on the right. */
@Composable
fun PageHeader(
    title: String,
    subtitle: String? = null,
    modifier: Modifier = Modifier,
    actions: @Composable RowScope.() -> Unit = {},
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = if (isDesktopLayout) 46.dp else 56.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = UiSize.pageTitleSp.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    fontSize = UiSize.rowSubtitleSp.sp,
                    color = AdGuardTextMuted,
                    maxLines = 2,
                    lineHeight = (UiSize.rowSubtitleSp + 3f).sp,
                )
            }
        }
        actions()
    }
}

/** A group's name above its rows: small, quiet, uppercase-free. */
@Composable
fun SectionLabel(
    text: String,
    modifier: Modifier = Modifier,
    trailing: @Composable RowScope.() -> Unit = {},
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(top = if (isDesktopLayout) 14.dp else 12.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = text,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 0.6.sp,
            color = AdGuardTextMuted,
            modifier = Modifier.weight(1f),
        )
        trailing()
    }
}

/** Hairline between rows; the only separator a desktop list needs. */
@Composable
fun RowDivider() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(AdGuardTextMuted.copy(alpha = 0.16f)),
    )
}

/**
 * One row of a settings or filter list: icon, title, quiet second line, and
 * the control the row exists for, pinned right.
 *
 * On a desktop the row is flat — the surface behind it is the page, as in
 * AdGuard for Windows. On a phone it keeps the rounded tile it always had,
 * because there a row is a target, not a line of a table.
 */
@Composable
fun FlatRow(
    title: String,
    subtitle: String? = null,
    icon: ImageVector? = null,
    iconTint: Color = AdGuardTextSecondary,
    tag: String? = null,
    enabled: Boolean = true,
    onClick: (() -> Unit)? = null,
    control: @Composable RowScope.() -> Unit = {},
) {
    val shape = RoundedCornerShape(if (isDesktopLayout) 8.dp else 14.dp)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (isDesktopLayout) Modifier
                else Modifier
                    .padding(vertical = 2.dp)
                    .clip(shape)
                    .background(AdGuardDarkSurface)
                    .border(1.dp, AdGuardTextMuted.copy(alpha = 0.16f), shape)
            )
            .then(if (onClick != null && enabled) Modifier.clickable(onClick = onClick) else Modifier)
            .then(if (tag != null) Modifier.testTag(tag) else Modifier)
            .padding(
                horizontal = if (isDesktopLayout) 10.dp else 12.dp,
                vertical = if (isDesktopLayout) 6.dp else 10.dp,
            )
            .heightIn(min = UiSize.rowMinHeight.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (enabled) iconTint else iconTint.copy(alpha = 0.4f),
                modifier = Modifier.size(if (isDesktopLayout) 18.dp else 20.dp),
            )
            Spacer(modifier = Modifier.width(if (isDesktopLayout) 12.dp else 12.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = UiSize.rowTitleSp.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (enabled) AdGuardTextPrimary else AdGuardTextMuted,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    fontSize = UiSize.rowSubtitleSp.sp,
                    color = AdGuardTextMuted,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    lineHeight = (UiSize.rowSubtitleSp + 3f).sp,
                )
            }
        }
        Spacer(modifier = Modifier.width(8.dp))
        control()
    }
}

/**
 * Rows with a hairline between them, no card, no gaps: the shape of every
 * list in AdGuard for Windows.
 */
@Composable
fun FlatGroup(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = if (isDesktopLayout) modifier.fillMaxWidth() else modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.Top,
        content = content,
    )
}

/**
 * The container a group of rows sits in.
 *
 * Phone: a rounded tile with an outline, because a phone list is a stack of
 * things you tap. Desktop: nothing at all — AdGuard for Windows puts rows on
 * the page surface and lets the hairlines do the work. Screens call this
 * instead of [androidx.compose.material3.Card] so switching bodies is one
 * line, not a rewrite.
 */
@Composable
fun SurfaceCard(
    modifier: Modifier = Modifier,
    tag: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val tagged = if (tag != null) modifier.testTag(tag) else modifier
    if (isDesktopLayout) {
        Column(modifier = tagged.fillMaxWidth()) { content() }
    } else {
        androidx.compose.material3.Card(
            modifier = tagged.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = androidx.compose.material3.CardDefaults.cardColors(
                containerColor = AdGuardDarkSurface,
            ),
            border = androidx.compose.foundation.BorderStroke(
                1.dp,
                AdGuardTextMuted.copy(alpha = 0.22f),
            ),
            content = content,
        )
    }
}
