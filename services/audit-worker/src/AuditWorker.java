import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AETHER MAIL audit-worker (Java 21).
 * Раз в минуту тянет события безопасности из Go API и агрегирует статистику.
 * Не имеет доступа к содержимому писем — только к типам событий.
 * Endpoints: GET /healthz, GET /stats
 */
public class AuditWorker {
    private static final String API_URL = env("API_INTERNAL", "http://api:8080");
    private static final String API_KEY = env("API_KEY", "");
    private static final long POLL_SECONDS = Long.parseLong(env("POLL_SECONDS", "60"));

    private static final Map<String, Long> byType = new LinkedHashMap<>();
    private static long total = 0;
    private static volatile String updated = "never";

    private static final Pattern TYPE_RE = Pattern.compile("\\\"type\\\":\\\"([^\\\"]+)\\\"");

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8092), 0);
        server.createContext("/healthz", ex -> respond(ex, 200, "{\"status\":\"ok\"}"));
        server.createContext("/stats", ex -> respond(ex, 200, statsJson()));
        server.start();
        System.out.println("audit-worker up on :8092, polling " + API_URL + " every " + POLL_SECONDS + "s");

        while (true) {
            try {
                poll();
            } catch (Exception e) {
                System.err.println("poll error: " + e.getMessage());
            }
            Thread.sleep(POLL_SECONDS * 1000);
        }
    }

    private static void poll() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL + "/v1/events?limit=10000"))
                .header("X-Api-Key", API_KEY)
                .GET()
                .build();
        HttpResponse<String> resp = HttpClient.newHttpClient()
                .send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            return;
        }
        Map<String, Long> counts = new LinkedHashMap<>();
        long n = 0;
        Matcher m = TYPE_RE.matcher(resp.body());
        while (m.find()) {
            counts.merge(m.group(1), 1L, Long::sum);
            n++;
        }
        synchronized (AuditWorker.class) {
            byType.clear();
            byType.putAll(counts);
            total = n;
            updated = Instant.now().toString();
        }
    }

    private static String statsJson() {
        synchronized (AuditWorker.class) {
            StringBuilder sb = new StringBuilder("{\"total\":").append(total)
                    .append(",\"updated\":\"").append(updated).append("\",\"by_type\":{");
            boolean first = true;
            for (Map.Entry<String, Long> e : byType.entrySet()) {
                if (!first) sb.append(',');
                sb.append('"').append(escape(e.getKey())).append("\":").append(e.getValue());
                first = false;
            }
            return sb.append("}}").toString();
        }
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes();
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    private static String env(String name, String def) {
        String v = System.getenv(name);
        return v == null || v.isEmpty() ? def : v;
    }
}
