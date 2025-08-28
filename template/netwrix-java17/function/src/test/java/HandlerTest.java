import org.junit.Test;
import static org.junit.Assert.*;

import com.accessanalyzer.function.Handler;
import com.accessanalyzer.model.IHandler;

public class HandlerTest {
    @Test public void handlerIsNotNull() {
        IHandler handler = new Handler();
        assertTrue("Expected handler not to be null", handler != null);
    }
}
