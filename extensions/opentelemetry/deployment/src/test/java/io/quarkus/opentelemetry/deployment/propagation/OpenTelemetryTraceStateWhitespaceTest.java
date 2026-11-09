package io.quarkus.opentelemetry.deployment.propagation;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.quarkus.test.QuarkusExtensionTest;
import io.restassured.RestAssured;

/**
 * Reproducer for CVE-2026-118259: a {@code tracestate} header containing long runs of whitespace not followed by a
 * comma must not cause quadratic CPU consumption when the W3C trace context is extracted from an incoming request.
 */
public class OpenTelemetryTraceStateWhitespaceTest {

    private static final String TRACE_ID = "0af7651916cd43dd8448eb211c80319c";
    private static final String TRACEPARENT = "00-" + TRACE_ID + "-b7ad6b7169203331-01";

    @RegisterExtension
    static final QuarkusExtensionTest unitTest = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClass(TestResource.class))
            .overrideRuntimeConfigKey("quarkus.http.limits.max-header-size", "256K");

    @Test
    @Timeout(30)
    void largeTraceStateWhitespaceIsParsedQuickly() {
        String padding = " ".repeat(100_000);

        // invalid list-member: the whole tracestate is dropped, but the traceparent is still honored
        assertThat(get("foo=bar" + padding + "x")).isEqualTo(TRACE_ID + "|");

        padding = "\t".repeat(100_000);
        assertThat(get("foo=bar" + padding + "x")).isEqualTo(TRACE_ID + "|");

        // optional whitespace around list-members is ignored
        assertThat(get("foo=bar" + padding + ",baz=qux")).isEqualTo(TRACE_ID + "|bar");
    }

    private static String get(String traceState) {
        long start = System.nanoTime();
        String body = RestAssured.given()
                .header("traceparent", TRACEPARENT)
                .header("tracestate", traceState)
                .get("/trace-state")
                .then()
                .statusCode(200)
                .extract().asString();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));
        return body;
    }

    @Path("/trace-state")
    public static class TestResource {

        @GET
        public String traceState() {
            SpanContext spanContext = Span.current().getSpanContext();
            String foo = spanContext.getTraceState().get("foo");
            return spanContext.getTraceId() + "|" + (foo == null ? "" : foo);
        }
    }
}
