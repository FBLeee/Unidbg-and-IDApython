
import flare_emu
import ida_ida
import idautils
import idaapi
import ida_segment
import idc
import ida_bytes
import re
import ida_bytes

from keystone import *

# arm 64位
# ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
# arm 32位
ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN)

# NOTE: BLOCK相关处理
def get_block_from_address(ea):
    func = idaapi.get_func(ea)
    if not func:
        print(f"No function found at address {ea:#x}")
        return None
    
    flowchart = idaapi.FlowChart(func)
    for block in flowchart:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None

def get_last_instruction_in_block(block):
    end_ea = block.end_ea
    current_ea = block.start_ea
    last_ea = current_ea

    for head in idautils.Heads(block.start_ea, end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            last_ea = head
    
    return last_ea




# NOTE: 得到代码段.text的起始和结束位置、size
def getAddrRange():
    start = ida_ida.inf_get_min_ea()
    size = ida_ida.inf_get_max_ea() - start
    # 将地址范围限定于text节
    for seg in idautils.Segments():
        seg = idaapi.getseg(seg)
        segName = ida_segment.get_segm_name(seg)
        if segName == ".text":
            start = seg.start_ea
            size = seg.size()
            end = start + size
    return start, end, size 


# NOTE: 通过二进制HEX值，寻找对应的sub函数的首地址
def binSearch(start, end, pattern):
    matches = []
    addr = start
    if end == 0:
        end = idc.BADADDR
    if end != idc.BADADDR:
        end = end + 1
    while True:
        addr = ida_bytes.bin_search(addr, end, bytes.fromhex(pattern), None, idaapi.BIN_SEARCH_FORWARD,
                                    idaapi.BIN_SEARCH_NOCASE)
        if addr == idc.BADADDR:
            break
        else:
            matches.append(hex(addr))
            addr = addr + 1
    return matches


# NOTE: unicorn模拟执行寻找R0、R1的值，并进行计算
# start_ea：调用计算函数sub地址所在block的起始地址
# call_ea：调用计算函数sub的地址
def get_register_values(start_ea,call_ea):
    myEH = flare_emu.EmuHelper()
    myEH.emulateRange(
    startAddr=start_ea,
    endAddr=call_ea
    )

    r0_value = myEH.getRegVal("R0")
    r1_value = myEH.getRegVal("R1")
    # .data段的偏移地址
    b_data_addr = r0_value + r1_value * 4
    # .text段的偏移地址
    b_text_name = idc.print_operand(b_data_addr,0)
    b_text_addr = b_text_name[4:]


    b_address = int(b_text_addr,16)

    return r0_value, r1_value, b_address

# NOTE: Patch
# instruction_address:  进行patch指令的偏移地址
# b_target_address： 最终需要跳转到的.text段的偏移地址
def patch_ida(instruction_address, b_target_address):

     # 替换 BX              R0  为 b jump_offset
    jump_offset = " ({:d})".format(b_target_address-instruction_address)
    # 替换后的指令  
    repair_opcode = 'b' + jump_offset
    # print("repair_opcode:",repair_opcode)
    encoding, count = ks.asm(repair_opcode)
    # encoding指令对应的机器码集合
    idaapi.patch_byte(instruction_address, encoding[0])
    idaapi.patch_byte(instruction_address + 1, encoding[1])
    idaapi.patch_byte(instruction_address + 2, encoding[2])
    idaapi.patch_byte(instruction_address + 3, encoding[3])




# FIXME 主要处理
def process_instructions(start_ea, end_ea, matches):
    current_ea = start_ea 
    while current_ea < end_ea:
        if idc.is_code(idc.get_full_flags(current_ea)):
            # FIXME 获取调用sub函数的地址，和汇编代码
            call_address = current_ea
            mnemonic = idc.print_insn_mnem(call_address)
            opnd1 = idc.print_operand(call_address, 0)
            opnd2 = idc.print_operand(call_address, 1)
            opnd3 = idc.print_operand(call_address, 2)

            # 打印或处理指令
            #print(f"{address:08X}: {mnemonic} {opnd1} {opnd2} {opnd3}")
            #print(mnemonic)
            if(mnemonic == 'BL' and opnd1.find("sub_") != -1):  #注意大小写
                opnd1_offset = "0x" + opnd1[4:]
                #print("opnd1_offset:",opnd1_offset)
                
                if(opnd1_offset.lower() in matches):
                    
                    
                    # 获取call_address地址所在的BLOCK
                    block = get_block_from_address(call_address)
                    if block:
                        #block 地址： [block.start_ea，block.end_ea)
						#print(f"Block start: {block.start_ea:#x}, end: {block.end_ea:#x} (exclusive)")
                        # 获取BLOCK最后一个指令的地址位置，即BX R0的地址位置
                        last_instr_addr = get_last_instruction_in_block(block)


                        # b_addr：最终需要跳转到的.text段的地址   B    b_addr
                        r0_val, r1_val, b_addr = get_register_values(block.start_ea,call_address)


                        # !最后需要patch的位置，将BX r0  替换为： B #0xxxx
                        # print(f"Last instruction in block(也是最后需要patch的地址): {last_instr_addr:#x}")

                        # 防止重复patch
                        disasm = idc.GetDisasm(last_instr_addr)
                        if(disasm == "BX              R0"):
                            # print("disasm:",disasm)
                            # FIXME Patch
                            patch_ida(last_instr_addr,b_addr)
                            # patch后，打印日志
                            print("\r\n")
                            print(f"{call_address:08X}: {mnemonic} {opnd1} {opnd2} {opnd3}       replace: B sub_{str(hex(b_addr))[2:]}")


                    else:
                        print(f"No block found at address {call_address:#x}")
                    
                    # break
                

        # 获取下一条指令的地址
        current_ea = idc.next_head(current_ea, end_ea)




# 获取.text代码段的起始地址和长度
start, end, size = getAddrRange()
codebytes = idc.get_bytes(start, size)
sub_matches = binSearch(0, 0, "01 01 90 E7 1E FF 2F E1")


print("sub_matches:",sub_matches)


# 遍历该段的所有指令
process_instructions(start, end, sub_matches)
