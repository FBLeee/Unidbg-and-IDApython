package com.kanxue.antiOllvm;

// 导入通用且标准的类库

import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Stack;

// 继承AbstractJni类
public class AntiOllvm extends AbstractJni {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private DalvikModule dm;
    // JNI_ONLoad函数的起始和结束地址
    private long start= 0x5E388;
    private long end = 0x5E7A0;
    /**instructions为Stck集合：指令栈，内部保存InsAndCtx类:【long addr;Instruction ins;List<Number> regs;和各种get、set方法】*/
    private Stack<InsAndCtx> instructions;

    /**patchs为List集合：内部保存所有需要patch的PatchIns类：【long addr; String ins;和各种get、set方法】*/
    private List<PatchIns> patchs;

    Util_antiOllvm util_antiOllvm;




    private static final String inName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out4.so";
    private static final String outName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out5.so";


    AntiOllvm() throws FileNotFoundException {

        //WARNING :一定要创建集合，否则会报错： Exception in thread "main" java.lang.IllegalStateException: Illegal JNI version: 0xffffffff
        instructions = new Stack<>();
        patchs = new ArrayList<>();
        //创建工具类
        util_antiOllvm = new Util_antiOllvm();


        // 创建一个模拟器实例,进程名建议依照实际的进程名填写，可以规避一些so中针对进程名校验
        emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).setProcessName("com.example.antiollvm").build();
        // 设置模拟器的内存操作接口(以此可以来做malloc等等内存操作了！！)
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析（自动加载了内存库）
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机,传入APK,Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM();
        // 加载so到虚拟内存,第二个参数的意思表示是否执行动态库的初始化代码
        // dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt.so"),true);
        dm = vm.loadLibrary(new File(inName), false);
        // 获取so模块的句柄
        module = dm.getModule();

        // explain 汇编指令级trace，并保存到文件path
        // String traceFile = "unidbg-android/src/test/resources/example_binaries/ollvm_fla/qxstrace.txt";
        // PrintStream traceStream = new PrintStream(new FileOutputStream(traceFile), true);
        // emulator.traceCode(module.base+0x5E388,module.base+0x5E7A0).setRedirect(traceStream);


        // 设置JNI
        vm.setJni(this);
        // 打印日志
        vm.setVerbose(true);

    };


    // NOTE 1. Unicorn HOOK并打印汇编指令
    // hook_add 添加一个Hook(后面的Hook参数通用，只有第一个不同)
    // 参数一：Hook回调
    // 参数二：Hook起始地址
    // 参数三：Hook结束地址
    // 参数四：自定义参数，可以在Hook的回调中拿到，也就是 Object user
    public void HookByUnicorn(){
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                //explain HOOK打印此时寄存器的值(arm64)
                // explain arm64
                // RegisterContext registerContext = emulator.getContext();
                // if(address == module.base + 0x97C){
                //     int r0 = registerContext.getIntByReg(Arm64Const.UC_ARM64_REG_X0);
                //     System.out.println("0x97C 处 r0:"+Integer.toHexString(r0));
                // }
                //
                // explain arm32
                // if(address == module.base + 0x97C + 2){
                //     int r2 = registerContext.getIntByReg(ArmConst.UC_ARM_REG_R2);
                //     System.out.println("0x97C +2 处 r2:"+Integer.toHexString(r2));
                // }
                // if(address == module.base + 0x97C + 4){
                //
                //     int r4 = registerContext.getIntByReg(ArmConst.UC_ARM_REG_R4);
                //     System.out.println("0x97C +4 处 r4:"+Integer.toHexString(r4));
                // }
                //explain hook并trace arm64汇编执行流程
                // explain arm32
                // Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM,Capstone.CS_MODE_THUMB);
                // byte[] bytes = emulator.getBackend().mem_read(address, size);
                // Instruction[] disasm = capstone.disasm(bytes, 0);
                // System.out.printf("%x:%s %s\n",address-module.base ,disasm[0].getMnemonic(),disasm[0].getOpStr());

                // explain arm64
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, size);
                Instruction[] disasm = capstone.disasm(bytes, 0);
                System.out.printf("%x:%s %s\n",address-module.base ,disasm[0].getMnemonic(),disasm[0].getOpStr());
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base + start, module.base + end, null);
    }

    // NOTE 2. 主动调用Jni_Onload函数
    public void callJniOnload()
    {
        dm.callJNI_OnLoad(emulator);
    }

    // NOTE 3. 对 Jni_OnLoad函数 进行指令栈trace，并将指令放入指令栈  Instructions 中, 并对花指令块进行处理do_processbr()
    public void processBr()
    {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] disasm = capstone.disasm(bytes, 0);

                //explain 3.1 创建 [保存指令和寄存器环境] 类
                InsAndCtx iac = new InsAndCtx();
                    //explain 3.1.1 保存指令
                iac.setIns(disasm[0]);
                    //explain 3.1.2 保存指令寄存器的上下文信息
                iac.setRegs(util_antiOllvm.saveRegs(backend));
                    //explain 3.1.3 保存指令的绝对地址（基址 + 偏移）
                iac.setAddr(address);

                //explain 3.2 将InsAndCtx类的变量iac放到 指令stack集合当中
                instructions.push(iac);

                //explain 3.3 调用处理函数，对相关cmp、csel等指令进行处理，看NOTE 4.
                do_processbr();
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("attach");
            }

            @Override
            public void detach() {
                System.out.println("detach");
            }
        },module.base+start, module.base+end,null);
    }

    // NOTE 4.指令栈回溯(对有BR X9 的代码块进行处理，do_processbr执行一次处理其中一整块数据)，根据处理结果，生成patchIns，供最后统一patch
    /**
     * 处理如下代码块
        CMP             W8, W27
        CSEL            X9, X28, X23, LT
        LDR             X9, [X19,X9]
        ADD             X9, X9, X24
        BR              X9
     */
    public void do_processbr()
    {
        Instruction ins = instructions.peek().getIns();

        //NOTE 5.通过控制下面的寄存器的值，来控制程序运行走向。
        // TODO 注意：只有在程序运行到汇编  “BR X9”  时，才会进行替换汇编指令操作do_processbr

        // WARNING : 对第一次的输出libtprt_out.so修改
        // private static final String inName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out.so";
        // private static final String outName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out1.so";

        // if(instructions.peek().getAddr() - module.base == 0x5E5AC)
        // {
        //     System.out.println("-------------W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W8,1);
        //     System.out.println("-------------W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        // }


        // WARNING : 对第二次的输出out1进行修改，使汇编一定要经过Br x9这个汇编指令，后续才能修改,对libtprt_out1.so修改
        // private static final String inName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out1.so";
        // private static final String outName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out2.so";

        // if(instructions.peek().getAddr() - module.base == 0x5E770)
        // {
        //     System.out.println("-------------5E770_W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W8,1);
        //     System.out.println("-------------5E770_W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        // }


        // WARNING : 对第三次的输出out2进行修改，使汇编一定要经过Br x9这个汇编指令，后续才能修改,对libtprt_out2.so修改
        // private static final String inName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out2.so";
        // private static final String outName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out3.so";

        // if(instructions.peek().getAddr() - module.base == 0x5E704)
        // {
        //     System.out.println("-------------5E770_W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W0,1);
        //     System.out.println("-------------5E770_W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        // }


        // WARNING : 对第四次的输出out3进行修改，使汇编一定要经过Br x9这个汇编指令，后续才能修改,对libtprt_out3.so修改
        // private static final String inName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out3.so";
        // private static final String outName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out4.so";

        // if(instructions.peek().getAddr() - module.base == 0x5E530)
        // {
        //     System.out.println("-------------5E770_W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W0,1);
        //     System.out.println("-------------5E770_W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        // }

        // WARNING : 对第五次的输出out4进行修改，使汇编一定要经过Br x9这个汇编指令，后续才能修改,对libtprt_out4.so修改
        // private static final String inName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out4.so";
        // private static final String outName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/tengxun.benghuai_110/libtprt_out5.so";

        // if(instructions.peek().getAddr() - module.base == 0x5E770)
        // {
        //     System.out.println("-------------5E770_W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W8,0);
        //     System.out.println("-------------5E770_W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        // }





















        if(ins.getMnemonic().equals("br") && ins.getOpStr().equals("x9"))
        {
            boolean finish = false;

            /* 该案列分析可知：X24是一个固定值*/
            long x24_reg_value = -1;

            /* 该案列分析可知：X19是一个数组，数组的偏移地址*/
            long listoffset = -1;
            /* CSEL指令中，第二个寄存器的值 */
            long cond1 = -1;
            /* CSEL指令中，第三个寄存器的值 */
            long cond2 = -1;
            /* 表示CSEL最后一个条件EQ、LT等 */
            String cond = "";

            /* add指令的偏移地址 */
            long add_instAddr = -1;
            /* br指令的偏移地址 */
            long br_instAddr = instructions.peek().getAddr() - module.base;
            /* csel指令的偏移地址 */
            long select_instAddr = -1;
            /* lda指令的偏移地址 */
            long lda_instAddr = -1;

            try {
                while (!finish && !instructions.empty())
                {
                    instructions.pop();
                    ins = instructions.peek().getIns();

                    // explain 4.1  处理 "ADD  X9, X9, X24" , 并保存 X24的值 、 ADD指令的偏移地址
                    if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("add"))
                    {
                        String[] split = ins.getOpStr().split(",");
                        if(split.length == 3)
                        {
                            if(split[0].toLowerCase(Locale.ROOT).trim().equals("x9") && split[1].toLowerCase(Locale.ROOT).trim().equals("x9"))
                            {
                                //reg名称
                                String reg = split[2].trim().toLowerCase(Locale.ROOT);
                                //根据上下文，获取此时X24寄存器的值
                                x24_reg_value = util_antiOllvm.getRegValue(reg,instructions.peek().getRegs()).longValue();
                                //获取ADD指令的偏移地址
                                add_instAddr = instructions.peek().getAddr() - module.base;
                            }
                            else {
                                break;
                            }
                        }
                        else
                        {
                            break;
                        }
                    }


                    // explain 4.2  处理 " LDR   X9, [X19,X9]" , 并保存 X19固定数组的偏移地址、LDR指令的偏移地址
                    if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("ldr"))
                    {
                        String[] sp = ins.getOpStr().toLowerCase().split(",");
                        //sp[0]: X9           sp[1]: [X19             sp[2]: X9]
                        if(sp.length == 3)
                        {
                            if(sp[0].trim().toLowerCase(Locale.ROOT).equals("x9") && sp[2].trim().toLowerCase(Locale.ROOT).equals("x9]"))
                            {
                                // reg：X19
                                String reg = sp[1].toLowerCase(Locale.ROOT).trim().substring(1);
                                listoffset = util_antiOllvm.getRegValue(reg,instructions.peek().getRegs()).longValue()-module.base;
                                lda_instAddr =  instructions.peek().getAddr()- module.base;
                            }
                        }
                    }


                    // explain 4.3  处理 " CSEL    X9, X28, X23, LT " , 并保存 X28、X23的值、条件LT、 CSEL指令的偏移地址
                    if(ins.getMnemonic().trim().toLowerCase(Locale.ROOT).equals("csel"))
                    {
                        String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                        if(sp.length == 4)
                        {
                            cond = sp[3].trim();
                            if(sp[0].trim().equals("x9"))
                            {
                                String reg1 = sp[1].trim();
                                String reg2 = sp[2].trim();
                                cond1 = util_antiOllvm.getRegValue(reg1,instructions.peek().getRegs()).longValue();
                                cond2 = util_antiOllvm.getRegValue(reg2,instructions.peek().getRegs()).longValue();
                                select_instAddr = instructions.peek().getAddr() - module.base;
                            }
                        }
                    }

                    // warning ：因为指令栈，所以先进后出，当处理到cmp指令时，说明该指令块即将执行完成了,因此可以进行patch了
                    // explain 4.4  处理 " CMP   W8, W27 " , 并保存 X28、X23的值，CSEL指令的偏移地址；
                    if(ins.getMnemonic().trim().toLowerCase(Locale.ROOT).equals("cmp"))
                    {
                        if(x24_reg_value == -1 || listoffset == -1 || cond1 == -1 || cond2 == -1 || cond.equals("") || add_instAddr == -1 || lda_instAddr == -1 || select_instAddr == -1)
                        {
                            break;
                        }
                        else
                        {
                            /*  X19是固定数组，X24是固定值

                                CMP             W8, W27
                                CSEL            X9, X28, X23, LT
                                LDR             X9, [X19,X9]
                                ADD             X9, X9, X24
                                BR              X9
                             */

                            // *x19+x28）+ x24  //记为addrT
                            // module.base+listoffset为固定数组的真实地址（基址+偏移）X19，
                            // util_antiOllvm.readInt64(emulator.getBackend(), module.base+listoffset+cond1)：就是 *(X19 + cond1)
                            long offset1 =  util_antiOllvm.readInt64(emulator.getBackend(), module.base+listoffset+cond1) - module.base  + x24_reg_value;
                            // *(x19+x23) + x24 //记为addrF。
                            long offset2 =  util_antiOllvm.readInt64(emulator.getBackend(), module.base+listoffset+cond2) - module.base  + x24_reg_value;

                            //当ADD下面BR X9时不符合当前案例，打印log
                            if( br_instAddr - add_instAddr != 4)
                            {
                                System.out.println("add ins and br ins gap more than 4 size,may make mistake");
                            }



                            /* 处理成如下：

                                    CMP            W8, W27
                                    NOP
                                    NOP
                                    BLT            addrT
                                    B              addrF

                            */
                            // offset1 ： *(x19+x28）+ x24  ，记为addrT；  offset1 - add_instAddr表示相对于add指令跳转地址，因为要覆盖add指令
                            String condBr = "b"+cond.toLowerCase(Locale.ROOT) + " 0x"+ Integer.toHexString((int) (offset1 - add_instAddr));
                            // offset2 ： *(x19+x23）+ x24  ，记为addrF；  offset2 - br_instAddr表示相对于br指令跳转地址，因为要覆盖br指令
                            String br = "b 0x" + Integer.toHexString((int)(offset2 - br_instAddr));

                            //覆盖ADD指令
                            PatchIns pi1 = new PatchIns();
                            pi1.setAddr(add_instAddr);
                            pi1.setIns(condBr);
                            patchs.add(pi1);

                            //覆盖BR指令
                            PatchIns pi2 = new PatchIns();
                            pi2.setAddr(br_instAddr);
                            pi2.setIns(br);
                            patchs.add(pi2);

                            //NOP CSEL 指令
                            PatchIns pi3 = new PatchIns();
                            pi3.setAddr(select_instAddr);
                            pi3.setIns("nop");
                            patchs.add(pi3);

                            //NOP LDR 指令
                            PatchIns pi4 = new PatchIns();
                            pi4.setAddr(lda_instAddr);
                            pi4.setIns("nop");
                            patchs.add(pi4);

                            //去除该块花指令完成标志！
                            finish = true;
                        }
                    }
                }
            }catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }

    //NOTE 5. 遍历patch表，执行patch，生成新的so，使用Ketstone将汇编转为机器码。
    public void patch()
    {
        try {
            File f = new File(inName);
            FileInputStream fis = new FileInputStream(f);
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            fis.close();
            for(PatchIns pi:patchs)
            {
                System.out.println("procrss addr:"+Integer.toHexString((int) pi.addr)+",code:"+pi.getIns());
                Keystone ks = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
                KeystoneEncoded assemble = ks.assemble(pi.getIns());
                for(int i=0;i<assemble.getMachineCode().length;i++)
                {
                    data[(int) pi.addr+i] = assemble.getMachineCode()[i];
                }
            }
            File fo = new File(outName);
            FileOutputStream fos = new FileOutputStream(fo);
            fos.write(data);
            fos.flush();
            fos.close();
            System.out.println("finish");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }




    //关闭模拟器实例
    private void destroy() throws IOException {
        emulator.close();
        // System.out.println("module=" + module);
        System.out.println("== destroy ===");
    }




    public static void main(String[] args) throws IOException {
        AntiOllvm antiOllvm = new AntiOllvm();
        //explain 主动调用JNIonload（trace或者 hook之后，才可以触发trace和hook）
        antiOllvm.HookByUnicorn();


        antiOllvm.processBr();

        antiOllvm.callJniOnload();


        antiOllvm.patch();



        antiOllvm.destroy();
    }

}
