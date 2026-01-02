package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Constant.RESULT_TRUSTED;

import android.util.Log;

import com.xiaotong.keydetector.checker.AOSPRootChecker;
import com.xiaotong.keydetector.checker.AttestationComplianceChecker;
import com.xiaotong.keydetector.checker.BinderHookChecker;
import com.xiaotong.keydetector.checker.BouncyCastleChainChecker;
import com.xiaotong.keydetector.checker.ChallengeChecker;
import com.xiaotong.keydetector.checker.Checker;
import com.xiaotong.keydetector.checker.KeyConsistencyChecker;
import com.xiaotong.keydetector.checker.RevokedKeyChecker;
import com.xiaotong.keydetector.checker.UnknownRootChecker;
import com.xiaotong.keydetector.checker.VBMetaChecker;

import java.util.LinkedHashMap;
import java.util.Map;

public final class DetectorEngine {
    public static final LinkedHashMap<Integer, Checker> FlagCheckerMap = new LinkedHashMap<>();
    static {
        FlagCheckerMap.put(4, new BinderHookChecker());
        FlagCheckerMap.put(8, new AOSPRootChecker());
        FlagCheckerMap.put(16, new UnknownRootChecker());
        FlagCheckerMap.put(32, new ChallengeChecker());
        FlagCheckerMap.put(64, new BouncyCastleChainChecker());
        FlagCheckerMap.put(128, new KeyConsistencyChecker());
        FlagCheckerMap.put(256, new RevokedKeyChecker());
        // idk how to re add 512 checker
        FlagCheckerMap.put(1024, new AttestationComplianceChecker());
        FlagCheckerMap.put(2048, new VBMetaChecker());
    }

    public int run(CheckerContext ctx) {
        int result = 0;

        for (Map.Entry<Integer, Checker> entry : DetectorEngine.FlagCheckerMap.entrySet()) {
            try {
                if (entry.getValue() == null) continue; // ?
                boolean hit = entry.getValue().check(ctx);
                if (hit) {
                    result |= entry.getKey();
                    Log.e("Detector", "Hit: " + entry.getValue().name()
                            + " flag=0x" + Integer.toHexString(entry.getKey()));
                }
            } catch (Throwable t) {
                Log.e("Detector", "Checker crashed: " + entry.getValue().name(), t);
                result |= 2;
            }
        }
        return Math.max(result, RESULT_TRUSTED);
    }
}
