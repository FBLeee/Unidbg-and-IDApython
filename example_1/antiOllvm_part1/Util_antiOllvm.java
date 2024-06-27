package com.kanxue.antiOllvm;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import unicorn.Arm64Const;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Util_antiOllvm {
    /**
     * 保存指令寄存器环境,即上下文信息
     * @param bk 上下文环境
     *
     * @return nb
     *      X0~X28 、FP、LR寄存器的值
     *
     * */
    // 这段代码的目的是保存一个 ARM64 环境中所有通用寄存器的状态，包括从 X0 到 X28，以及 FP（帧指针）和 LR（链接寄存器）。这个功能在模拟器或调试器中很常见，便于之后恢复这些寄存器的状态或者进行分析。为了更好地理解这段代码，我们可以进一步分析每个部分的功能，并且提供一些改进建议。
    public List<Number> saveRegs(Backend bk)
    {
        List<Number> nb = new ArrayList<>();
        for(int i=0;i<29;i++)
        {
            //i+ Arm64Const.UC_ARM64_REG_X0: 计算出每个寄存器的编号，因为java无法动态生成变量名
            // bk.reg_read: 调用 Backend 实例的方法读取寄存器的值
            nb.add(bk.reg_read(i+ Arm64Const.UC_ARM64_REG_X0));
        }
        nb.add(bk.reg_read(Arm64Const.UC_ARM64_REG_FP));
        nb.add(bk.reg_read(Arm64Const.UC_ARM64_REG_LR));
        return nb;
    }

    /**
     * 读取指令寄存器环境,即读取上下文信息
     * @param reg
     *          寄存器名字
     * @param regsaved
     *          依次保存X0-X28、FP、LR寄存器的List
     *
     * @return 查询指定寄存器的值
     * */
    public Number getRegValue(String reg,List<Number> regsaved)
    {
        if(reg.equals("xzr"))
        {
            return 0;
        }
        else if(reg.equals("fp")){
            return regsaved.get(29);
        }
        else if(reg.equals("lr")){
            return regsaved.get(30);
        }

        return regsaved.get(Integer.parseInt(reg.substring(1)));
    }


    public long readInt64(Backend bk,long addr)
    {
        byte[] bytes = bk.mem_read(addr, 8);
        long res = 0;
        for (int i=0;i<bytes.length;i++)
        {
            res =((bytes[i]&0xffL) << (8*i)) + res;
        }
        return res;
    }












}


/** InsAndCtx: 保存指令和寄存器环境类 */
class InsAndCtx
{
    long addr;
    Instruction ins;
    List<Number> regs;

    public long getAddr() {
        return addr;
    }

    public void setAddr(long addr) {
        this.addr = addr;
    }

    public void setIns(Instruction ins) {
        this.ins = ins;
    }

    public Instruction getIns() {
        return ins;
    }

    public void setRegs(List<Number> regs) {
        this.regs = regs;
    }

    public List<Number> getRegs() {
        return regs;
    }
}

/** PatchIns：patch类,patch 地址 和 指令*/
class PatchIns{
    long addr;//patch 地址
    String ins;//patch的指令

    public long getAddr() {
        return addr;
    }

    public void setAddr(long addr) {
        this.addr = addr;
    }

    public String getIns() {
        return ins;
    }

    public void setIns(String ins) {
        this.ins = ins;
    }
}


