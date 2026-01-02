package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Util.getSystemProperty;
import static com.xiaotong.keydetector.Util.hexStringToByteArray;

import android.util.Log;

import com.xiaotong.keydetector.CheckerContext;
import com.xiaotong.keydetector.RootOfTrust;

import java.util.Arrays;

public final class VBMetaChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        final byte[] systemVBMetaDigest = hexStringToByteArray(getSystemProperty("ro.boot.vbmeta.digest"));
        RootOfTrust rot = RootOfTrust.parse(ctx.certChain.get(0));
        if (rot == null) return true;
        Log.d("VBMetaChecker", "rot: " + rot);
        boolean digestEqualsHash = !Arrays.equals(systemVBMetaDigest, rot.getVerifiedBootHash());
        boolean digestEqualsKey = !Arrays.equals(systemVBMetaDigest, rot.getVerifiedBootKey());
        boolean bootStateUnverified = rot.getVerifiedBootState() != 0; // UNVERIFIED
        boolean deviceUnlocked = !rot.getDeviceLocked();
        return digestEqualsHash
                || digestEqualsKey
                || bootStateUnverified
                || deviceUnlocked;
    }

    @Override
    public String description() {
        return "VBMeta Mismatch (%d)\nVBMeta Hash 不一致或设备已解锁";
    }
}