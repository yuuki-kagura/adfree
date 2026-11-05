package git.shin.adfree.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density

private val DarkColorScheme = darkColorScheme(
    primary = AdGuardDarkColors.greenPrimary,
    onPrimary = Color.Black,
    primaryContainer = AdGuardDarkColors.greenDark,
    onPrimaryContainer = Color.White,
    secondary = AdGuardDarkColors.blueDns,
    onSecondary = Color.Black,
    secondaryContainer = AdGuardDarkColors.surfaceVariant,
    onSecondaryContainer = Color.White,
    tertiary = AdGuardDarkColors.redBlocked,
    onTertiary = Color.White,
    background = AdGuardDarkColors.bg,
    onBackground = AdGuardDarkColors.textPrimary,
    surface = AdGuardDarkColors.surface,
    onSurface = AdGuardDarkColors.textPrimary,
    surfaceVariant = AdGuardDarkColors.surfaceVariant,
    onSurfaceVariant = AdGuardDarkColors.textSecondary,
    outline = AdGuardDarkColors.outline,
    outlineVariant = AdGuardDarkColors.outline.copy(alpha = 0.5f),
)

private val LightColorScheme = lightColorScheme(
    primary = AdGuardLightColors.greenPrimary,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFC4EFD9),
    onPrimaryContainer = Color(0xFF00210F),
    secondary = AdGuardLightColors.blueDns,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD3E9F7),
    onSecondaryContainer = Color(0xFF001E30),
    tertiary = AdGuardLightColors.redBlocked,
    onTertiary = Color.White,
    background = AdGuardLightColors.bg,
    onBackground = AdGuardLightColors.textPrimary,
    surface = AdGuardLightColors.surface,
    onSurface = AdGuardLightColors.textPrimary,
    surfaceVariant = AdGuardLightColors.surfaceVariant,
    onSurfaceVariant = AdGuardLightColors.textSecondary,
    outline = AdGuardLightColors.outline,
    outlineVariant = AdGuardLightColors.outline.copy(alpha = 0.5f),
)

/** Labels were laid out at 9-13sp; scale text without resizing dp containers. */
private const val FontScale = 1.2f

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false, // Keep AdGuard's branded colors
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val palette = if (darkTheme) AdGuardDarkColors else AdGuardLightColors
    val density = LocalDensity.current

    CompositionLocalProvider(
        LocalAdGuardColors provides palette,
        LocalDensity provides Density(
            density = density.density,
            fontScale = density.fontScale * FontScale,
        )
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = Typography,
            content = content
        )
    }
}
