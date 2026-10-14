package git.shin.adfree.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

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

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true, // AdGuard signature dark cybersecurity look
    dynamicColor: Boolean = false, // Keep AdGuard's branded colors
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
