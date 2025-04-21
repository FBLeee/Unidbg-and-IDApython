package com.kanxue.antiOllvm;

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
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Stack;

public class AntiOllvm_part2 {
    private AndroidEmulator emulator;
    private VM vm;
    private DalvikModule dm;
    private Module module;
    private long start= 0x5E388;
    private long end = 0x5E7A0;
    private Stack<InsAndCtx> instructions;
    private List<PatchIns> patchs;
    private static final String inName = "unidbg-android/src/test/resources/tengxun/benghuai/libtprt_out5.so";
    private static final String outName = "unidbg-android/src/test/resources/tengxun/benghuai/libtprt_ollvm_out.so";
    //主分发器的起始地址
    private static final long dispatcher = 0x5E46C;
    private static final long toend = 0x5E6BC;
    //记录真实块，index是寄存器的值，startAddress是此值对应的真实块的起始地址
    private List<TrueBlock>tbs;
    //记录条件块
    private List<selectBr> sbs ;
    //记录索引顺序
    private List<Long> indexOrder;

    //去混淆工具类
    Util_antiOllvm_part2 util_antiOllvm_part2;


    public AntiOllvm_part2()
    {
        //指令栈容器
        instructions = new Stack<>();
        patchs = new ArrayList<>();
        //tbs 是存储 真是块TrueBlock 对象的列表。
        tbs = new ArrayList<>();
        //如果下一条指令是 csel（条件选择），并且涉及 w8 寄存器，则创建一个 selectBr 实例，设置其条件、真值索引和假值索引，并将其添加到 sbs 列表中。
        sbs = new ArrayList<>();
        //如果当前指令块中的跳转地址等于 dispatcher（主要分发器地址），获取指令块X8的寄存器值，并添加到 indexOrder 列表中。
        indexOrder = new ArrayList<>();

        //创建工具类
        util_antiOllvm_part2 = new Util_antiOllvm_part2();

        //创建模拟器
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.antiollvm")
                .build();
        Memory memory = emulator.getMemory();
        //设置andorid系统库版本
        memory.setLibraryResolver(new AndroidResolver(23));
        //创建虚拟机
        vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        //加载动态库,此方式会报错，用sdk 23，unidbg自带系统库
        // vm.loadLibrary(new File("unidbg-android/src/test/resources/android.arm64/libc.so"),false);
        // vm.loadLibrary(new File("unidbg-android/src/test/resources/android.arm64/libm.so"),false);
        // vm.loadLibrary(new File("unidbg-android/src/test/resources/android.arm64/libstdc++.so"),false);
        // vm.loadLibrary(new File("unidbg-android/src/test/resources/android.arm64/ld-android.so"),false);
        // vm.loadLibrary(new File("unidbg-android/src/test/resources/android.arm64/libdl.so"),false);
        dm = vm.loadLibrary(new File(inName), false);
        module = dm.getModule();


    }


    // NOTE 1. Unicorn HOOK trace汇编指令
    // hook_add 添加一个Hook(后面的Hook参数通用，只有第一个不同)
    // 参数一：Hook回调
    // 参数二：Hook起始地址
    // 参数三：Hook结束地址
    // 参数四：自定义参数，可以在Hook的回调中拿到，也就是 Object user
    public void HookByUnicornTraceIns()
    {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user)  {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                //arm64中4字节一跳指令
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] disasm = capstone.disasm(bytes, 0);
                System.out.printf("%x:%s %s\n",address-module.base ,disasm[0].getMnemonic(),disasm[0].getOpStr());
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base+start, module.base+end, null);
    }

    // NOTE 2. 主动调用Jni_Onload函数，触发hook
    public void callJniOnload()
    {
        dm.callJNI_OnLoad(emulator);
    }



    // NOTE 3.下面的hook JNI_OnLoad函数，打印所有执行的arm汇编指令，并将其以对象InsAndCtx存储在栈容器instructions中
    public void processFlt()
    {

        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] disasm = capstone.disasm(bytes, 0);
                InsAndCtx iac = new InsAndCtx();
                iac.setIns(disasm[0]);
                // 该指令中所有寄存器的值
                iac.setRegs(util_antiOllvm_part2.saveRegs(backend));
                iac.setAddr(address);
                instructions.add(iac);
                //explain 3.1 对trace的汇编进行追踪，提取真实块地址 和 【cmp W8，index值】
                do_processflt();
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("attach");
            }

            @Override
            public void detach() {
                System.out.println("detach");
            }
        },module.base+start, module.base+end, null);
    }




    // NOTE 3.1 思路
        /*
        所以我们可以按照以下算法对控制流平坦化进行还原：

        1.建立一个指令栈，每条指令执行前，保留该指令的地址，指令内容，当前所有寄存器的值。然后将当前指令的信息push进指令栈。


        2.对指令进行回溯，如果栈顶指令是b.eq，则进行3（收集真实块），如果栈顶指令是直接跳转指令b，则进行5（处理分支块），否则继续执行下一条指令。


        3.向上回溯指令栈，找到第一条cmp 指令，判断是否为与索引寄存器w8 比较，如果是，则进行4，否则继续执行下一条指令。


        4.获取与w8比较的另一个寄存器的值，获取b.eq的目标地址，组成一个（索引，真实块）对。继续执行下一条指令。


        5.判断上一条指令是否为CSEL W8。如果是，则记录一个（条件成立块索引，条件不成立块索引）对。否则，继续执行下一条指令。


        同时，我们在主分发器处hook 指令，记录每次经过主分发器时的索引寄存器的值为索引值顺序。
        */

    // NOTE 3.2 instructions存储每个执行过的arm汇编指令，以InsAndCtx对象存储（保存指令和寄存器环境类），
    //  （1）对每个指令进行处理，获取与w8比较的另一个寄存器的值，获取b.eq的目标地址，组成一个（索引，真实块地址）对；------------->注意，这是trace时，程序按照原逻辑所走的一个分支的真实块；然而另一个分支需要手动更改条件触发，才能知道另一个分支的真实块地址，即4.4
    //  （2）对每个指令进行处理，判断上一条指令是否为CSEL W8。如果是，则记录一个（条件成立块索引，条件不成立块索引）对
    public void do_processflt()
    {
        //对输出out5进行修改，强制其执行if中的另一个分支
        // if(instructions.peek().getAddr() - module.base == 0x5E5AC)
        // {
        //     System.out.println("-------------W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W8,1);
        //     System.out.println("-------------W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        // }

        //对输出out5进行修改，强制其执行if中的另一个分支
        // if(instructions.peek().getAddr() - module.base == 0x5E770)
        // {
        //     System.out.println("-------------W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X8,0);
        //     System.out.println("-------------W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue());;
        // }

        //对输出out5进行修改，强制其执行if中的另一个分支
        // if(instructions.peek().getAddr() - module.base == 0x5E530)
        // {
        //     System.out.println("-------------W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W0).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W0,1);
        //     System.out.println("-------------W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W0).intValue());;
        // }



        //对输出out5进行修改，强制其执行if中的另一个分支
        // if(instructions.peek().getAddr() - module.base == 0x5E704)
        // {
        //     System.out.println("-------------W8_before:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W0).intValue());;
        //     emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W0,1);
        //     System.out.println("-------------W8_after:" + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W0).intValue());;
        // }



        if(instructions.empty())
        {
            return;
        }
        Instruction ins = instructions.peek().getIns();
        if(instructions.peek().getAddr() - module.base == dispatcher)
        {
            indexOrder.add(util_antiOllvm_part2.getRegValue("x8",instructions.peek().getRegs()).longValue());
        }



        /* 示例1
            .text:000000000005E58C loc_5E58C                               ; CODE XREF: JNI_OnLoad+1FC↑j
            .text:000000000005E58C                 CMP             W8, W22
            .text:000000000005E590                 MOV             W9, #0x118
            .text:000000000005E594                 MOV             W2, #0xE0
            .text:000000000005E598                 NOP
            .text:000000000005E59C                 NOP
            .text:000000000005E5A0                 B.EQ            loc_5E5A8 ； 用unidbg执行就是 beq.getIns().getOpStr().toLowerCase(Locale.ROOT);  为b.eq #8
            .text:000000000005E5A4                 B               loc_5E46C ；主分发器

            通过trace知道，经主分发器分发的下一个真实块地址，从而达到收集真实块的目的（通过控制条件，可以找到if所有分支的跳转真实块的地址）

        */
        // NOTE 3.2.1 栈顶指令是b.eq，则进行3（收集真实块）==========》  目标：找到所有的 【寄存器的值作为索引，跳转的真实块地址作为value】； 后面3.2.2也是按照此设置寄存器的值，从而之后可以通过寄存器值来获取跳转真实块地址
        if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("b.eq")) {
            InsAndCtx beq = instructions.peek();
            //等于跳转，检查是否为cmp x8,
            while (true)
            {
                if(instructions.empty())
                {
                    break;
                }
                instructions.pop();
                ins = instructions.peek().getIns();
                if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("cmp"))
                {

                    String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                    if(sp[0].equals("w8"))
                    {
                        //找到一个真实块
                        TrueBlock tb = new TrueBlock();
                        // W22的值
                        long regValue = util_antiOllvm_part2.getRegValue(sp[1].trim(), instructions.peek().getRegs()).longValue();
                        long targetAddr = 0;
                        String offset = beq.getIns().getOpStr().toLowerCase(Locale.ROOT);   //IDA反编译是：B.EQ            loc_5E5A8， 但是unidbg打印出来的就是  b.eq #8； #8相对当前地址的偏移
                        /*相对当前位置的偏移  #8 */
                        long offsetvalue = util_antiOllvm_part2.getLongFromOpConst(offset);
                        /*targetAddr：目标偏移地址，相对module.base的偏移地址*/
                        targetAddr = beq.getAddr() + offsetvalue - module.base;
                        tb.setIndex(regValue);
                        //需要跳转过去的目标偏移地址（相对module.base来说）
                        tb.setStartAddr(targetAddr);
                        // 获取与w8比较的另一个寄存器的值，获取b.eq的目标地址，组成一个（索引，真实块）对
                        tbs.add(tb);
                        break;
                    }
                }
            }
        }




        //warning 注意区分：
        // 在part1阶段，目的：花指令处理的是只处理 带有 BR X9指令的块，将其变成两个B指令，去掉花指令；
        // 在part2阶段，目的：将  “真实块1---> 主分发器 ---> 真实块2  ”       ===变成==》       “真实块1---> 真实块2”
        //处理分支块


        
        /* 示例2
                处理前：  ***************************根据规律可以发现：    
                上一个CSEL的 [CMP + B.EQ] 真实块 --->  这一个CSEL真假控制块 ---> 主分发器 ---> 这一个CSEL的[CMP + B.EQ] 真实块；
                
                因为之前【3.2.1 】已经找到 {寄存器的值作为索引：对应的真实块地址作为value}
                所以此处直接按照CSEL的两个寄存器的值[w11的值  和 W12的值]设置【sb.setTrueindex，sb.setFalseindex】。那么后续就可以通过这个寄存器的值，读取各自寄存器值对应的真实块地址了，这样就直接连起来了！！！！！



                
                .text:000000000005E58C loc_5E58C                               ; CODE XREF: JNI_OnLoad+1FC↑j
                .text:000000000005E58C                 CMP             W8, W22
                .text:000000000005E590                 MOV             W9, #0x118
                .text:000000000005E594                 MOV             W2, #0xE0
                .text:000000000005E598                 NOP
                .text:000000000005E59C                 NOP
                .text:000000000005E5A0                 B.EQ            loc_5E5A8
                .text:000000000005E5A4                 B               loc_5E46C ; 此为主分发器
                .text:000000000005E5A8 ; ---------------------------------------------------------------------------
                .text:000000000005E5A8
                .text:000000000005E5A8 loc_5E5A8                               ; CODE XREF: JNI_OnLoad+218↑j
                .text:000000000005E5A8                 LDR             W8, [SP,#0x80+var_5C]
                .text:000000000005E5AC                 CMP             W8, #0
                .text:000000000005E5B0                 CSEL            W8, W11, W12, EQ
                .text:000000000005E5B4                 B               loc_5E46C ; 此为主分发器


                处理后为：

                .text:000000000005E5A8 loc_5E5A8                               ; CODE XREF: JNI_OnLoad:loc_5E46C↑j
                .text:000000000005E5A8                                         ; JNI_OnLoad+218↑j
                .text:000000000005E5A8                 LDR             W8, [SP,#0x80+var_5C]
                .text:000000000005E5AC                 CMP             W8, #0
                .text:000000000005E5B0                 B.EQ            loc_5E764
                .text:000000000005E5B4                 B               loc_5E6B0


        */
        // NOTE 3.2.2 如果栈顶指令是直接跳转指令b，则进行5（处理分支块），记录一个（条件成立块对应的寄存器值，条件不成立块对应的寄存器值）对
        if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("b"))
        {
            long offset = util_antiOllvm_part2.getLongFromOpConst(ins.getOpStr());
            if(offset != 0)
            {
                //下一个b所跳转到的偏移地址
                long target = offset + instructions.peek().getAddr() - module.base;
                //如果下一跳是跳到主分生器，那么就处理
                if(target == dispatcher)
                {
                    instructions.pop();
                    ins = instructions.peek().getIns();
                    if(ins.getMnemonic().toLowerCase(Locale.ROOT).equals("csel"))
                    {
                        String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                        if(sp[0].trim().equals("w8"))
                        {
                            // EQ LT等
                            String cond = sp[3].trim();
                            //两个分支
                            String reg1 = sp[1].trim();
                            String reg2 = sp[2].trim();

                            //设置分支对象
                            selectBr sb = new selectBr();

                            // CSEL指令的偏移地址（相对于module.base）
                            sb.setInsaddr(instructions.peek().getAddr() - module.base);
                            sb.setCond(cond);
                            sb.setTrueindex(util_antiOllvm_part2.getRegValue(reg1,instructions.peek().getRegs()).longValue());
                            sb.setFalseindex(util_antiOllvm_part2.getRegValue(reg2,instructions.peek().getRegs()).longValue());
                            sbs.add(sb);
                        }
                    }
                }
            }
        }
    }







    public static void main(String[] args) {
        AntiOllvm_part2 antiOllvm_part2 = new AntiOllvm_part2();
        // trace原有的执行轨迹
        antiOllvm_part2.HookByUnicornTraceIns();
        // Unicorn hook trace  并在trace时寻找真实块进行处理
        antiOllvm_part2.processFlt();

        //触发hook trace
        antiOllvm_part2.callJniOnload();


        //打印真实块信息
        antiOllvm_part2.reorderblock();

        //patch
        antiOllvm_part2.patch();

    }





    //NOTE 5. 执行patch
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




    // index： CMP指令中，获取与w8比较的另一个寄存器的值，获取b.eq的目标地址，组成一个（索引，真实块）对
    private long getIndexAddr(long index)
    {
        //tbs是真是块
        for(TrueBlock tb:tbs)
        {
            if(tb.getIndex() == index)
            {
                return tb.getStartAddr();
            }
        }
        System.out.printf("not found addr for index:%x,result may be wrong!\n",index);
        return -1;
    }

    // NOTE 4.打印各个 真实块/分支块 的起始地址
    private void reorderblock()
    {
        //NOTE 4.4  手动更改分支条件，让程序触发另一分支，从而根据trace的指令，得到另一个分支真实块的起始地址，手动加入即可(必须在此函数最开始加入，因为后面会通过getIndexAddr访问)
        //查看他们的索引，发现刚好是条件块中的索引。这个也好理解，因为在模拟执行的时候我们只走了条件的一个分支，没有走另一个分支，所以就没有记录下对应的真实块。这里我们手动根据b.eq和寄存器的值，添加对应的真实块：
        // 通过修改   CMP             W8, #0  ; 更改分支2   ，然后找到 b.eq 后面的真实块即可
        //warning  处理完4.2和4.3后，才能处理4.4，这样才能保持原有的整体逻辑。
        // explain
        //  问：这一分支，程序原有逻辑没有经过，为什么要处理4.4？
        //  答：一个app的不同动作对if的不同分支都可能触发，那么我们根据程序运行的主要逻辑，找到另一个分支真实块，这样代码还原时，才不会缺省。
        //手动添加另一分支，程序自己运行了一个分支（所以这一部分不用我们添加）
        tbs.add(new TrueBlock(0x6e142ec8L,0x5E6B0));
        tbs.add(new TrueBlock(0xf07b1447L,0x5E608));
        tbs.add(new TrueBlock(0x5d7b4e5aL,0x5E5E8));
        tbs.add(new TrueBlock(0x5ad22f2fL,0x5E628));



        for(TrueBlock tb:tbs)
        {
            System.out.printf("true block index %x,addr %x\n",tb.getIndex(),tb.getStartAddr());
        }
        for(selectBr sb:sbs)
        {
            //真假分支有前面的CSEL来控制的
            //  sb.getTrueindex():真分支对应的寄存器的值       sb.getFalseindex()：假分支对应的寄存器的值     
            System.out.printf("select block inds addr: %x,cond: %s . true for %x,false for %x\n",sb.getInsaddr(),sb.getCond(),sb.getTrueindex(),sb.getFalseindex());
        }

        for(long l:indexOrder)
        {
            System.out.printf("index order:%x\n",l);
        }


        // NOTE 4.1 处理条件块：根据CSEL指令计算出两个分支的真实块地址，去掉 “跳到主分发器” 的过程
        //sbs 记录条件块
        //处理分支块
        /* 示例2
                .text:000000000005E5A8 loc_5E5A8                               ; CODE XREF: JNI_OnLoad+218↑j
                .text:000000000005E5A8                 LDR             W8, [SP,#0x80+var_5C]
                .text:000000000005E5AC                 CMP             W8, #0
                .text:000000000005E5B0                 CSEL            W8, W11, W12, EQ
                .text:000000000005E5B4
                .text:000000000005E5B4 loc_5E5B4
                .text:000000000005E5B4                 B               loc_5E46C ; 主分发器

                处理后为：

                .text:000000000005E5A8 loc_5E5A8                               ; CODE XREF: JNI_OnLoad:loc_5E46C↑j
                .text:000000000005E5A8                                         ; JNI_OnLoad+218↑j
                .text:000000000005E5A8                 LDR             W8, [SP,#0x80+var_5C]
                .text:000000000005E5AC                 CMP             W8, #0
                .text:000000000005E5B0                 B.EQ            loc_5E764
                .text:000000000005E5B4                 B               loc_5E6B0


        */
        for(selectBr sb:sbs)
        {
            // warning getIndexAddr(sb.getTrueindex()) 是 拿到   【3.2.1】通过定位 B.EQ找到的 {寄存器值：B.EQ的地址}   的B.EQ的地址
            // warning 减去sb.getInsaddr()的目的是得到 Trueindex真实块地址和CSEL指令地址之间的差距值
            String ins1 = "b" + sb.getCond() + " 0x"+Integer.toHexString((int) (getIndexAddr(sb.getTrueindex()) -  sb.getInsaddr()));
            String ins2 = "b 0x"+ Integer.toHexString((int) (getIndexAddr(sb.getFalseindex())-sb.getInsaddr()-4));
            PatchIns pi1 = new PatchIns();
            pi1.setIns(ins1);
            //在CSEL指令处patch  B.EQ   0xTrueindex相对CSEL地址的差距值
            pi1.setAddr(sb.getInsaddr());
            PatchIns pi2 = new PatchIns();
            pi2.setIns(ins2);
            //在CSEL 的下一条指令处patch  B.EQ   0xFalseindex相对CSEL地址的差距值 - 4 （因为CSEL在上面arm64偏移4位）
            pi2.setAddr(sb.getInsaddr() + 4);
            //pach 两条指令
            patchs.add(pi1);
            patchs.add(pi2);
        }

        // NOTE 4.2 处理第一个真实块（让主分发器跳转到 第一个真实块）：获取索引值顺序中的第一个值，找到对应的真实块。将主分发器处patch为跳转向第一个真实块的跳转指令。
        // 看trace的汇编指令来判断下面的值
        // 考虑到编译的结果要在逻辑上和原来的代码完全一致，所以一个重要的结论是——真实的代码块一定在cmp b.eq 之后。（switch case 的一个case）
        // 从前往后看，让主分发器跳转到 第一个真实块（trace指令中的第一个b.eq后的地址），所以计算第一个真实块起始地址相对于主分发器的起始地址的偏移：【getIndexAddr(0x22f0693f)-dispatcher)】
        PatchIns pi = new PatchIns();
        pi.setAddr(dispatcher);
        //dispatcher : 0x5E46C 主分发器起始地址
        pi.setIns("b 0x"+Integer.toHexString((int) (getIndexAddr(0x22f0693f)-dispatcher)));
        patchs.add(pi);



        // NOTE 4.3 处理最后一个真实块（找前面的True/False真实块）：根据真实块结束时的新的索引值，寻找到对应的真实块A，将真实块A的结尾处patch为跳转到最后一个真实块B。
        //      做法：将跳到主分发器的前一个真实块的最后指令的地址，替换成直接跳转到下一个真实块地址
        //      注意：trace指令时，b.eq后面的地址就是真实块地址（通过控制条件，找到True/Flase真实块）
        // 从后往前看，找到最后一个真实块前的两个真实块（true真实块、false真实块）； 替换b #0xfffffffffffffdf8 为跳转跳转到两个真实块（true真实块、false真实块）（定位到trace指令中的最后一个b.eq，往前找b指令的地址）
        // NOTE 4.3.1 处理true真实块
        // 0x5E674L真实块的下一跳是包含ret的真实块，即最后一块真实块的前真实块
        PatchIns pie1 = new PatchIns();
        // true block index 83a9af56, 下一个对应的真实块地址addr 5e77c，然后寻找前面的b指令，发现trace指令时，看到如下
        // 5e674:b #0xfffffffffffffdf8
        // 5e46c:cmp w8, w27
        // 5e470:nop
        // 5e474:nop
        // ...
        // ...
        // 5e4c0:b.eq #0x2bc
        // 5e77c:ldr x8, [sp, #0x18]     //注：0x5e77c最后一个真实块的起始地址（包含RET指令）
        //所以找到相对b指令的地址（ 0x5E674），即跳转的偏移量： getIndexAddr(0x83a9af56L) - 0x5E674L
        pie1.setAddr(0x5E674L);
        pie1.setIns("b 0x"+Integer.toHexString((int) (getIndexAddr(0x83a9af56L) - 0x5E674L)));
        patchs.add(pie1);

        // NOTE 4.3.2 处理false真实块
        // 从后往前看，找到最后一个真实块前的两个真实块（true真实块、false真实块）； 替换b #0xfffffffffffffdf8 为跳转跳转到两个真实块（true真实块、false真实块）（定位到trace指令中的最后一个b.eq，往前找b指令的地址）
        // toend ：0x5E6BC，通过改变之前的if来改变执行分支，找到最后一个包含真实块ret，上一个真实块：false真实块
        PatchIns pie = new PatchIns();
        pie.setAddr(0x5e6bc);
        pie.setIns("b 0x"+Integer.toHexString((int) (getIndexAddr(0x83a9af56L)- 0x5e6bc)));
        patchs.add(pie);




    }



}
