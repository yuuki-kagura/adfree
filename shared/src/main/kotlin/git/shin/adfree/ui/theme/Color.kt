package git.shin.adfree.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * Every role the screens paint with.
 *
 * The screens were written against dark-only constants; going through a
 * palette keeps those call sites unchanged while letting the whole app follow
 * the selected theme.
 */
@Immutable
data class AdGuardColors(
    val greenPrimary: Color,
    val greenLight: Color,
    val greenDark: Color,
    val greenGlow: Color,
    val bg: Color,
    val surface: Color,
    val surfaceVariant: Color,
    val outline: Color,
    val redBlocked: Color,
    val redBg: Color,
    val blueDns: Color,
    val blueBg: Color,
    val orangeWarning: Color,
    val orangeBg: Color,
    val purpleAI: Color,
    val purpleBg: Color,
    /** Text/icons drawn on top of the accent (green) fill. */
    val onAccent: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textMuted: Color,
)

val AdGuardDarkColors = AdGuardColors(
    greenPrimary = Color(0xFF00D06C),
    greenLight = Color(0xFF22E685),
    greenDark = Color(0xFF00964D),
    greenGlow = Color(0x3300D06C),
    bg = Color(0xFF0A0E13),
    surface = Color(0xFF131920),
    surfaceVariant = Color(0xFF1B242E),
    outline = Color(0xFF283645),
    redBlocked = Color(0xFFFF435A),
    redBg = Color(0x22FF435A),
    blueDns = Color(0xFF00B0FF),
    blueBg = Color(0x2200B0FF),
    orangeWarning = Color(0xFFFF9800),
    orangeBg = Color(0x22FF9800),
    purpleAI = Color(0xFFB388FF),
    purpleBg = Color(0x22B388FF),
    onAccent = Color.Black,
    textPrimary = Color(0xFFF3F6F9),
    textSecondary = Color(0xFF8B9DAF),
    textMuted = Color(0xFF5A6C7D),
)

/**
 * The light counterpart. The accents keep the same hue but sit darker: the
 * bright dark-theme green is unreadable as text on white.
 */
val AdGuardLightColors = AdGuardColors(
    greenPrimary = Color(0xFF008A4A),
    greenLight = Color(0xFF00733D),
    greenDark = Color(0xFF00622F),
    greenGlow = Color(0x33008A4A),
    bg = Color(0xFFF3F7F4),
    surface = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFE6EEE8),
    outline = Color(0xFFC2CFC6),
    redBlocked = Color(0xFFC62E45),
    redBg = Color(0x1FC62E45),
    blueDns = Color(0xFF0B6FA8),
    blueBg = Color(0x1F0B6FA8),
    orangeWarning = Color(0xFFA86400),
    orangeBg = Color(0x1FA86400),
    purpleAI = Color(0xFF6A45C7),
    purpleBg = Color(0x1F6A45C7),
    onAccent = Color.White,
    textPrimary = Color(0xFF10201A),
    textSecondary = Color(0xFF4B6156),
    textMuted = Color(0xFF75877C),
)

val LocalAdGuardColors = staticCompositionLocalOf { AdGuardDarkColors }

val AdGuardGreenPrimary: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.greenPrimary

val AdGuardGreenLight: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.greenLight

val AdGuardGreenDark: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.greenDark

val AdGuardGreenGlow: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.greenGlow

val AdGuardDarkBg: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.bg

val AdGuardDarkSurface: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.surface

val AdGuardDarkSurfaceVariant: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.surfaceVariant

val AdGuardDarkOutline: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.outline

val AdGuardRedBlocked: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.redBlocked

val AdGuardRedBg: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.redBg

val AdGuardBlueDns: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.blueDns

val AdGuardBlueBg: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.blueBg

val AdGuardOrangeWarning: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.orangeWarning

val AdGuardOrangeBg: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.orangeBg

val AdGuardPurpleAI: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.purpleAI

val AdGuardPurpleBg: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.purpleBg

val AdGuardOnAccent: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.onAccent

val AdGuardTextPrimary: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.textPrimary

val AdGuardTextSecondary: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.textSecondary

val AdGuardTextMuted: Color
    @Composable @ReadOnlyComposable get() = LocalAdGuardColors.current.textMuted
