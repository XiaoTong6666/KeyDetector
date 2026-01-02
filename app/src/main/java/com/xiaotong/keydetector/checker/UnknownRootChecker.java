package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.ROOT_UNKNOWN;

import com.xiaotong.keydetector.CheckerContext;

public final class UnknownRootChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        return ctx.rootType == ROOT_UNKNOWN;
    }

    @Override
    public String description() {
        return "Unknown Attestation Key (%d)\n根证书未知";
    }
}