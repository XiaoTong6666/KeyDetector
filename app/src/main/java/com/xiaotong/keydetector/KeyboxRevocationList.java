package com.xiaotong.keydetector;

import android.content.Context;
import android.content.res.Resources;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class KeyboxRevocationList {
    private static final String TAG = "KeyboxRevocationList";
    private static volatile Map<String, RevocationEntry> sEntries;

    public static final class RevocationEntry {
        final String status;
        final String reason;

        RevocationEntry(String status, String reason) {
            this.status = status;
            this.reason = reason;
        }

        public boolean isRevoked() {
            return "REVOKED".equalsIgnoreCase(status);
        }
    }

    static boolean isRevoked(Context context, String serialHex) {
        RevocationEntry entry = getEntry(context, serialHex);
        return entry != null && entry.isRevoked();
    }

    static Set<String> getRevokedSerialHex(Context context) {
        if (context == null) return Collections.emptySet();
        Map<String, RevocationEntry> entries = getEntries(context);
        HashSet<String> out = new HashSet<>(entries.size() * 4 / 3 + 1);
        for (Map.Entry<String, RevocationEntry> e : entries.entrySet()) {
            if (e.getValue() != null && e.getValue().isRevoked()) {
                out.add(e.getKey());
            }
        }
        return out;
    }

    public static RevocationEntry getEntry(Context context, String serialHex) {
        if (context == null || serialHex == null) return null;
        String normalized = serialHex.trim().toLowerCase(Locale.US);
        if (normalized.isEmpty()) return null;
        return getEntries(context).get(normalized);
    }

    static Map<String, RevocationEntry> getEntries(Context context) {
        Map<String, RevocationEntry> cached = sEntries;
        if (cached != null) return cached;
        synchronized (KeyboxRevocationList.class) {
            cached = sEntries;
            if (cached != null) return cached;
            cached = loadFromStatusJson(context);
            sEntries = cached;
            return cached;
        }
    }

    private static Map<String, RevocationEntry> loadFromStatusJson(Context context) {
        if (context == null) {
            Log.w(TAG, "Context is null; revocation list disabled.");
            return Collections.emptyMap();
        }

        try {
            Resources res = context.getResources();
            try (InputStream in = res.openRawResource(R.raw.status)) {
                JSONObject root = new JSONObject(readUtf8(in));
                JSONObject entries = root.optJSONObject("entries");
                if (entries == null) entries = root;

                HashMap<String, RevocationEntry> out = new HashMap<>(entries.length() * 4 / 3 + 1);
                Iterator<String> it = entries.keys();
                while (it.hasNext()) {
                    String key = it.next();
                    if (key == null) continue;
                    Object entry = entries.opt(key);
                    if (!(entry instanceof JSONObject)) continue;
                    String normalized = key.trim().toLowerCase(Locale.US);
                    if (normalized.isEmpty()) continue;
                    String status = ((JSONObject) entry).optString("status", "");
                    String reason = ((JSONObject) entry).optString("reason", "");
                    out.put(normalized, new RevocationEntry(status, reason));
                }
                return Collections.unmodifiableMap(out);
            }
        } catch (Throwable t) {
            Log.w(TAG, "Failed to load revocation list from status.json", t);
            return Collections.emptyMap();
        }
    }

    private static String readUtf8(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(16 * 1024);
        byte[] buf = new byte[8192];
        int read;
        while ((read = in.read(buf)) != -1) {
            out.write(buf, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private KeyboxRevocationList() {
    }
}
