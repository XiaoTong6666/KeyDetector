package com.xiaotong.keydetector.checker;

import com.xiaotong.keydetector.CheckerContext;

public abstract class Checker {
    /** checker 名字，仅用于 log */
    public abstract String name();

    /**
     * @return true  = 命中（异常 / 特征存在）
     *         false = 未命中
     */
    public abstract boolean check(CheckerContext ctx) throws Exception;

    public abstract String description();
}