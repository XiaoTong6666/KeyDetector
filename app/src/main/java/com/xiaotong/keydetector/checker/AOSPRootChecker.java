package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.ROOT_AOSP;

import com.xiaotong.keydetector.CheckerContext;

public final class AOSPRootChecker extends Checker {

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception{
        return ctx.rootType == ROOT_AOSP;
    }

    @Override
    public String description() {
        return "AOSP Attestation Key (%d)\n检测到软件级 (AOSP) 根证书";
    }
}