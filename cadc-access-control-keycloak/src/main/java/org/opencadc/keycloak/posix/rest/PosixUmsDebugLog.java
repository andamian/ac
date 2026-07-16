package org.opencadc.keycloak.posix.rest;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Debug-mode NDJSON logger for UMS configuration startup.
 */
final class PosixUmsDebugLog {

    private static final Path LOG_PATH = Path.of(
            "/Users/adriand/Documents/work/github/ac/.cursor/debug-019ba0.log");

    private PosixUmsDebugLog() {
    }

    static void log(String hypothesisId, String location, String message, Map<String, Object> data) {
        // #region agent log
        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("sessionId", "019ba0");
            payload.put("hypothesisId", hypothesisId);
            payload.put("location", location);
            payload.put("message", message);
            payload.put("data", data);
            payload.put("timestamp", System.currentTimeMillis());
            String line = toJson(payload);
            Path logPath = resolveLogPath();
            Files.writeString(logPath, line + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            System.err.println("AGENT_DEBUG " + line);
        } catch (Exception ignored) {
            // debug logging must not affect startup
        }
        // #endregion
    }

    private static Path resolveLogPath() {
        String override = System.getenv("DEBUG_AGENT_LOG");
        if (override != null && !override.trim().isEmpty()) {
            return Path.of(override.trim());
        }
        return LOG_PATH;
    }

    static String summarizePropertyNames(Set<String> names) {
        if (names == null || names.isEmpty()) {
            return "";
        }
        return names.stream().sorted().collect(Collectors.joining(","));
    }

    private static String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escape(entry.getKey())).append("\":");
            sb.append(toJsonValue(entry.getValue()));
        }
        sb.append('}');
        return sb.toString();
    }

    private static String toJsonValue(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> nested = (Map<String, Object>) value;
            return toJson(nested);
        }
        return "\"" + escape(String.valueOf(value)) + "\"";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
