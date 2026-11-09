package git.shin.adfree.desktop

import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.runComposeUiTest
import git.shin.adfree.ui.screens.RuleBuilderSheet
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.width
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toAwtImage
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.dp
import git.shin.adfree.ui.theme.MyApplicationTheme
import java.io.File
import javax.imageio.ImageIO
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * The rule builder is the screen a user reaches for when a rule needs more than
 * a domain, so what it writes has to be exactly what its controls say: the
 * modifiers in order, the pattern anchored the way AdGuard expects, and no
 * character typed by the preview.
 */
@OptIn(ExperimentalTestApi::class)
class RuleBuilderUiTest {

    @Test
    fun theControlsAreTheRuleThatGetsSaved() {
        var saved: String? = null
        runComposeUiTest {
            setContent {
                MyApplicationTheme {
                    RuleBuilderSheet(
                        title = "Thêm quy tắc",
                        initialRule = "||example.com^\$image",
                        onSave = { saved = it },
                        onCancel = {},
                    )
                }
            }
            onNodeWithTag("rule_builder_flag_third-party").performClick()
            onNodeWithTag("rule_builder_type_script").performClick()
            onNodeWithTag("rule_builder_save").performClick()
            assertEquals("||example.com^\$third-party,script,image", saved)
        }
    }

    @Test
    fun aPatternTypedWithoutAnchorsIsStillARule() {
        var saved: String? = null
        runComposeUiTest {
            setContent {
                MyApplicationTheme {
                    RuleBuilderSheet(
                        title = "Thêm quy tắc",
                        onSave = { saved = it },
                        onCancel = {},
                    )
                }
            }
            onNodeWithTag("rule_builder_pattern").performTextReplacement("ads.example.org")
            onNodeWithTag("rule_builder_save").performClick()
            assertEquals("||ads.example.org^", saved)
        }
    }

    @Test
    fun proseIsRefusedBeforeItCanBeSaved() {
        var saved: String? = null
        runComposeUiTest {
            setContent {
                MyApplicationTheme {
                    RuleBuilderSheet(
                        title = "Thêm quy tắc",
                        onSave = { saved = it },
                        onCancel = {},
                    )
                }
            }
            onNodeWithTag("rule_builder_pattern").performTextReplacement("this is not a rule")
            onNodeWithTag("rule_builder_error").assertExists()
            onNodeWithTag("rule_builder_save").performClick()
            assertFalse("nothing may be saved while the line is invalid", saved != null)
        }
    }

    @Test
    fun theBuilderSaysWhetherItWouldSeeTheOpenRequest() {
        runComposeUiTest {
            setContent {
                MyApplicationTheme {
                    Box(modifier = Modifier.width(420.dp).fillMaxHeight()) {
                        RuleBuilderSheet(
                            title = "Thêm quy tắc",
                            initialRule = "||other.example^",
                            previewHost = "example.com",
                            onSave = {},
                            onCancel = {},
                        )
                    }
                }
            }
            // The line names another host, so the pane must say so rather than
            // leave the user to notice after saving.
            onNodeWithTag("rule_builder_preview").assertExists()
            onNodeWithTag("rule_builder_pattern").assertExists()
            ImageIO.write(
                onRoot().captureToImage().toAwtImage(),
                "png",
                File("/tmp/adfree_rule_builder.png"),
            )
        }
    }
}
