package git.shin.adfree.desktop

import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.runComposeUiTest
import androidx.compose.ui.test.waitUntilAtLeastOneExists
import androidx.compose.ui.graphics.toAwtImage
import java.io.File
import javax.imageio.ImageIO
import org.junit.Test

/**
 * Drives the real desktop UI headlessly: the Compose test scene renders
 * against the software Skia surface and [DesktopEngine] loads the actual
 * libadfree_core.so through the shared JNA bindings, so the verdict rows
 * below are genuine core output.
 */
@OptIn(ExperimentalTestApi::class)
class DesktopUiTest {
    @Test
    fun rendersEngineStatusWithRealCoreVerdicts() {
        runComposeUiTest {
            setContent { DesktopApp() }

            onNodeWithText("AdFree").assertExists()
            onNodeWithText("Engine").assertExists()
            onNodeWithText("Check").assertExists()
            onNodeWithText("Engine status").assertExists()

            waitUntilAtLeastOneExists(hasText("Active rules"), 60_000)
            onNodeWithText("Data root").assertExists()
            onNodeWithText("Filter build").assertExists()
            onNodeWithText("clean").assertExists()

            check(onAllNodes(hasText("blocked by", substring = true)).fetchSemanticsNodes().size == 2) {
                "expected two blocked probe hosts"
            }
            check(onAllNodes(hasText("allowed")).fetchSemanticsNodes().size == 2) {
                "expected two allowed probe hosts"
            }
            val image = onRoot().captureToImage().toAwtImage()
            ImageIO.write(image, "png", File("/tmp/adfree_ui_test.png"))
        }
    }

    @Test
    fun hostCheckScreenRespondsToInput() {
        runComposeUiTest {
            setContent { DesktopApp() }
            onNodeWithText("Check").performClick()
            waitUntilAtLeastOneExists(hasText("Hostname"), 60_000)
            onNodeWithText("doubleclick.net").assertExists()
        }
    }
}
