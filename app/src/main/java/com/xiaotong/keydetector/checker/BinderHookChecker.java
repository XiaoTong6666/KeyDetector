package com.xiaotong.keydetector.checker;

import com.xiaotong.keydetector.CheckerContext;
import com.xiaotong.keydetector.handler.BinderHookHandler;

public final class BinderHookChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception{
        return !BinderHookHandler.installHook();
    }

    @Override
    public String description() {
        return "Hook Failed (%d)\n尝试 Hook ServiceManager 失败";
    }
}