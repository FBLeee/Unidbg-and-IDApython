#代码来自：https://bbs.kanxue.com/thread-277428.htm(某手游xqtd的简单分析,2beNo2)

import idautils
import idc
import idaapi
import ida_ua
from keystone import *
 
g_reg = [0] * 40
# X0的编号和索引值
reg_base = 129
g_cond_info = list()
ldr_reg = -1
add_reg = -1
 
ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
 
def get_opcode(ea):
    opcode = None
    disasm = idc.GetDisasm(ea)
    if disasm.find('LT') != -1:
        opcode = 'blt'
    elif disasm.find('EQ') != -1:
        opcode = 'beq'
    elif disasm.find('CC') != -1:
        opcode = 'bcc'
    elif disasm.find('GT') != -1:
        opcode = 'bgt'
    elif disasm.find('NE') != -1:
        opcode = 'bne' 
    elif disasm.find('GE') != -1:
        opcode = 'bge' 
    elif disasm.find('HI') != -1:
        opcode = 'bhi' 
    return opcode
 
 
def do_patch(patch_1, patch_2, opcode, cond_jmp_addr, uncond_jmp_addr):
    print("patch_1=0x%x patch_1=0x%x opcode=%s cond_jmp_addr=0x%x uncond_jmp_addr=0x%x" % (patch_1, patch_2, opcode, cond_jmp_addr, uncond_jmp_addr))
 
    jump_offset = " ({:d})".format(cond_jmp_addr - patch_1)
    print("jump_offset:",jump_offset)
    repair_opcode = opcode + jump_offset
    encoding, count = ks.asm(repair_opcode)
    idaapi.patch_byte(patch_1, encoding[0])
    idaapi.patch_byte(patch_1 + 1, encoding[1])
    idaapi.patch_byte(patch_1 + 2, encoding[2])
    idaapi.patch_byte(patch_1 + 3, encoding[3])
 
    jump_offset = " ({:d})".format(uncond_jmp_addr - patch_2)
    repair_opcode = 'b' + jump_offset
    encoding, count = ks.asm(repair_opcode)
    idaapi.patch_byte(patch_2, encoding[0])
    idaapi.patch_byte(patch_2 + 1, encoding[1])
    idaapi.patch_byte(patch_2 + 2, encoding[2])
    idaapi.patch_byte(patch_2 + 3, encoding[3])
 
 
def do_deobf(ea):
    # !获取跳转条件
    opcode = get_opcode(ea)
    if opcode is None:
        print("opcode:unknown opcode 0x%x" % ea)
        return ea
 
    # !获取跳转信息CSEL/CSET
    csel_addr = ea
    cond_reg = -1
    uncond_reg = -1
    cond_data = -1
    uncond_data = -1
    mnem = idc.ida_ua.ua_mnem(ea)
    # 对CSEL指令处理：CSEL            X9, X28, X23, LT
    if mnem == 'CSEL':
        # 获取X28寄存器的编号
        cond_reg = idc.get_operand_value(ea, 1)
        # 获取X23寄存器的编号
        uncond_reg = idc.get_operand_value(ea, 2)
    elif mnem == 'CSET':
        cond_data = 1
        uncond_data = 0
    # 获取下一条指令的地址
    ea = idc.next_head(ea)
    
    # !获取LDR寄存器
    # 举例说明： LDR             X9, [X19,X9]
    ldr_addr = ea
    ldr_reg = -1
    lsl_value = -1
    mnem = idc.ida_ua.ua_mnem(ea)
    
    if mnem == 'LSL':
        lsl_value = idc.get_operand_value(ea, 2)
        ea = idc.next_head(ea)
        mnem = idc.ida_ua.ua_mnem(ea)
 
    if mnem != 'LDR':
        print("LDR:0x%x -> %s" % (ea, mnem))
        return ea
 
    operand_type = idc.get_operand_type(ea, 1)
    # o_phrase， 3 ，短语操作数，表示根据寄存器和偏移量计算的内存地址。
    if operand_type == idc.o_phrase:
        # 创建一个指令对象
        insn = ida_ua.insn_t()
        # 解码 ea 处的指令，并将解码结果存入 insn。
        ida_ua.decode_insn(insn, ea)
        # 将 LDR 指令的第二个操作数寄存器赋值给 ldr_reg，即为：X19寄存器的编号或索引
        # Op索引从1开始
        ldr_reg = insn.Op2.reg
        
        # 获取第二操作数的值,因为是寄存器，寄存器操作数的相关信息通常存储在 insn.Op2.reg 字段中，而 insn.Op2.value 字段通常未被使用或保留为默认值0
    # if op2_type == ida_ua.o_imm:
    #     op2_value = insn.Op2.value
    #     print(f"立即数值: {op2_value}")
    # elif op2_type == ida_ua.o_mem:
    #     op2_addr = insn.Op2.addr
    #     print(f"内存地址: {op2_addr}")
    # elif op2_type == ida_ua.o_reg:
    #     op2_reg = insn.Op2.reg
    #     print(f"寄存器编号: {op2_reg}")
    # else:
    #     print("第二操作数是其他类型。")
        if lsl_value == -1:
            # 所以当op2是寄存器时，此肯定为0，只有为立即数时才有输出
            lsl_value = insn.Op2.value
    else:
        return ea
    
    # 获取下一条指令的地址
    ea = idc.next_head(ea)
 
    # !获取ADD寄存器
    # 举例说明：ADD             X9, X9, X24
    # 获取ea地址处汇编指令的助记符
    add_addr = ea
    mnem = idc.ida_ua.ua_mnem(ea)
    # 获取MOV的下一个指令的助记符
    if mnem == 'MOV':
        ea = idc.next_head(ea)
        mnem = idc.ida_ua.ua_mnem(ea)
    #如果不是ADD指令，打印地址和助记符
    if mnem != 'ADD':
        print("获取ADD寄存器:0x%x -> %s" % (ea, mnem))
        return ea
    # 获取指定地址 addr 的汇编指令的第 index 个操作数（字符串形式），如果 index 索引超过操作数的个数则返回空字符串，X24
    # 索引从0开始
    op_3 = idc.print_operand(ea, 2)
    # 得到寄存器相对于X0的偏移编号，24
    op_3 = op_3[1:]

    # 获取下一条指令的地址
    ea = idc.next_head(ea)

    # !进行patch
    mnem = idc.ida_ua.ua_mnem(ea)
    if mnem != 'BR':
        print("BR:0x%x -> %s" % (ea, mnem))
        return ea
 
    #print('1 = %d 2 = %d 3 = 0x%x' % (g_reg[ldr_reg - reg_base],  g_reg[cond_reg - reg_base], g_reg[int(op_3)]))
    if cond_data != -1 and uncond_data != -1:
        print("lsl_value:",lsl_value)
        cond_jmp_addr  = (idc.get_qword(g_reg[ldr_reg - reg_base] + (cond_data << lsl_value)) + g_reg[int(op_3)]) & 0xffffffffffffffff
        
        uncond_jmp_addr = (idc.get_qword(g_reg[ldr_reg - reg_base] + (uncond_data << lsl_value)) + g_reg[int(op_3)]) & 0xffffffffffffffff
    
    
  
    else:

        # text:000000000005E46C                  CMP             W8, W27
        # .text:000000000005E470                 CSEL            X9, X28, X23, LT
        # .text:000000000005E474                 LDR             X9, [X19,X9]
        # .text:000000000005E478                 ADD             X9, X9, X24
        # .text:000000000005E47C                 BR              X9

        # *（x19+x28）+x24  //记为addrTrue。
        cond_jmp_addr   = (idc.get_qword(g_reg[ldr_reg - reg_base] + (g_reg[cond_reg - reg_base] << lsl_value)) + g_reg[int(op_3)]) & 0xffffffffffffffff
        # *(x19+x23)+x24 //记为addrFalse。
        uncond_jmp_addr = (idc.get_qword(g_reg[ldr_reg - reg_base] + (g_reg[uncond_reg - reg_base] << lsl_value)) + g_reg[int(op_3)]) & 0xffffffffffffffff
        print("---"*20) 
        print("lsl_value:",lsl_value)
        print("当前处理的汇编语句块为: ")
        print("\t",idc.GetDisasm(csel_addr-4))
        print("\t",idc.GetDisasm(csel_addr))
        print("\t",idc.GetDisasm(ldr_addr))
        print("\t",idc.GetDisasm(add_addr))
        print("\t",idc.GetDisasm(ea))

        print("[X19 - X0]:",ldr_reg - reg_base)
        print("X19的值（即：X19表示的数组的地址）:0x%x"% g_reg[ldr_reg - reg_base])
        print("LDR             X9, [X19,X9] 中 [X9 - X0]:",cond_reg - reg_base)
        print("X9的值:0x%x"%g_reg[cond_reg - reg_base])
        print("*(X19+X9):0x%x"%idc.get_qword(g_reg[ldr_reg - reg_base] + (g_reg[cond_reg - reg_base] << lsl_value)))  
        print("*(X19):0x%x"%idc.get_qword(g_reg[ldr_reg - reg_base]))   
        print("[x24 - X0]:",int(op_3))
        print("X24的值:0x%x"%g_reg[int(op_3)])
        print("True分支的真实块地址:0x%x"%cond_jmp_addr)
        print("False分支的真实块地址:0x%x"%uncond_jmp_addr)
        print("====="*20 + "\r\n")

        print("lsl_value:",lsl_value,"    cond_jmp_addr:%x"%cond_jmp_addr,"   uncond_jmp_addr:%x"%uncond_jmp_addr)
    # do_patch(idc.prev_head(ea), ea, opcode, cond_jmp_addr, uncond_jmp_addr)
    return ea
 
 
def deobf(ea):
    off_reg = -1
    off_data = -1
    # 给寄存器数组g_reg赋值0~39相对X0的编号
    while True:
        mnem = idc.ida_ua.ua_mnem(ea)
        if mnem == 'RET':
            break
        elif mnem == 'MOV':
            op_1_type = idc.get_operand_type(ea, 0)
            op_2_type = idc.get_operand_type(ea, 1)
            if (op_1_type == idc.o_reg) and (op_2_type == idc.o_imm):
                op_1 = idc.get_operand_value(ea, 0)
                op_2 = idc.get_operand_value(ea, 1)
                g_reg[op_1 - reg_base] = op_2
        elif mnem == 'MOVK':
            op_1_type = idc.get_operand_type(ea, 0)
            op_2_type = idc.get_operand_type(ea, 1)
            op_3_type = idc.get_operand_type(ea, 2)
            if (op_1_type == idc.o_reg) and (op_2_type == idc.o_imm):
                op_1 = idc.get_operand_value(ea, 0)
                op_2 = idc.get_operand_value(ea, 1)
                g_reg[op_1 - reg_base] = (op_2 << 16) | (g_reg[op_1 - reg_base] & 0xffff)
        elif mnem == 'ADRP':
            op_1 = idc.get_operand_value(ea, 0)
            op_2 = idc.get_operand_value(ea, 1)
            off_reg = op_1
            off_data = op_2
        elif mnem == 'ADD':
            op_1 = idc.get_operand_value(ea, 0)
            op_2 = idc.get_operand_value(ea, 1)
            op_3 = idc.get_operand_value(ea, 2)
            op_3_type = idc.get_operand_type(ea, 2)
            if (op_1 == off_reg) and (op_2 == off_reg) and (op_3_type == idc.o_imm):
                off_data = off_data + op_3
                ldr_reg = off_reg - reg_base
                g_reg[ldr_reg] = off_data 
        elif mnem == 'CMP':
            # 获取第一个寄存器的编号
            op_1 = idc.get_operand_value(ea, 0)
            print("cmp W%d"%(int(op_1) - reg_base) ,"0x%x"%g_reg[op_1 - reg_base])
            # print("CMP X%s:0x%x"%(op_1,g_reg[op_1 - reg_base]))

            # !op_2 = idc.get_operand_value(ea, 1)获取第二个寄存器的编号,这个值打印永远是-1，不知什么原因,W寄存器不太适用这个函数？
            operand = idc.print_operand(ea, 1)
            sec_reg_num = int(operand[1:])
            print("cmp W%d"%sec_reg_num,"0x%x"%g_reg[sec_reg_num])
        
            # print("cmp W%d"%(int(op_2) - reg_base) ,"0x%x"%g_reg[op_2 - reg_base])
            # print("cmp 0x%x", int(op_2) ,"0x%x"%g_reg[op_2 - reg_base])
            # print("CMP X%s:0x%x"%(op_2,g_reg[op_2 - reg_base]))

        elif (mnem == 'CSEL') or (mnem == 'CSINC') or (mnem == 'CSET') or (mnem == 'CINC'):
            ea = do_deobf(ea)
            continue
        ea = idc.next_head(ea)
 
 
def test():
    for i in range(len(g_reg)):
        print("%d:0x%x" % (i, g_reg[i]))
 
 
def main():
    ea = idc.get_screen_ea()
    func = idaapi.get_func(ea)
    ea = func.start_ea
    print("start deobf fun:0x%x" %(ea))
    deobf(ea)
    print("deobf ok!")
    # test()
    pass
 
if __name__ == "__main__":
    main()
