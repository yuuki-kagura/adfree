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
    primary = AdGuardGreenPrimary,
    onPrimary = Color.Black,
    primaryContainer = AdGuardGreenDark,
    onPrimaryContainer = Color.White,
    secondary = AdGuardBlueDns,
    onSecondary = Color.Black,
    secondaryContainer = AdGuardDarkSurfaceVariant,
    onSecondaryContainer = Color.White,
    tertiary = AdGuardRedBlocked,
    onTertiary = Color.White,
    background = AdGuardDarkBg,
    onBackground = AdGuardTextPrimary,
    surface = AdGuardDarkSurface,
    onSurface = AdGuardTextPrimary,
    surfaceVariant = AdGuardDarkSurfaceVariant,
    onSurfaceVariant = AdGuardTextSecondary,
    outline = AdGuardDarkOutline,
    outlineVariant = AdGuardDarkOutline.copy(alpha = 0.5f)
)

private val LightColorScheme = darkColorScheme( // AdGuard looks best in dark mode; provide crisp fallback
    primary = AdGuardGreenPrimary,
    onPrimary = Color.Black,
    primaryContainer = AdGuardGreenLight,
    onPrimaryContainer = Color.Black,
    secondary = AdGuardBlueDns,
    onSecondary = Color.White,
    background = AdGuardDarkBg,
    onBackground = AdGuardTextPrimary,
    surface = AdGuardDarkSurface,
    onSurface = AdGuardTextPrimary,
    surfaceVariant = AdGuardDarkSurfaceVariant,
    onSurfaceVariant = AdGuardTextSecondary,
    outline = AdGuardDarkOutline
)

/** Labels were laid out at 9-13sp; scale text without resizing dp containers. */
private const val FontScale = 1.2f

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true, // AdGuard signature dark cybersecurity look
    dynamicColor: Boolean = false, // Keep AdGuard's branded colors
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val density = LocalDensity.current

    CompositionLocalProvider(
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
