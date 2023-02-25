
来源 网络 未知
https://github.com/zengfr/ida-pro-idb-database/tree/main/demo/2

https://github.com/liyansong2018/unitracer/blob/main/README_zh.md

"""
【依赖调用了其他so函数的情况下就不能像之前例子这样调用了】
实现对 so 中函数调用
int add_six(char* flag,int b,int c, int d, int e,int f){
    int sum=0;
    if(strstr(flag, "add")){
        sum=add(sum,c);
        sum=add(sum,d);
    }else{
        sum=add(sum,e);
        sum=add(sum,f);
    }
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_zok_uni_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    int sum=add(3,4);
    sum=add_six("flag",2,3,4,5,6);
    return env->NewStringUTF(hello.c_str());
}
"""
import unicorn
import capstone
import binascii
import struct
# 取出 so 内容
with open("so/callstrstr.so",'rb') as f:
    CODE=f.read() 
def capstone_print(code, offset):
    """capstone 测试输出"""
    print("\033[1;32m-------- capstone 输出--------\033[0m")
    CP = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)  # 指定 THUMB 指令集
    for i in CP.disasm(code[offset:], 0, 20):  
        print('\033[1;32m地址: 0x%x | 操作码: %s | 内容: %s\033[0m'%(offset + i.address, i.mnemonic, i.op_str))
def uni_add_six():
    """6个参数超过 amr32 4个寄存器，需要将多的2个参数放到堆栈当中"""
    print('-------- unicorn 执行前--------')
    # 1. 创建实例
    mu = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)  # 要指定架构和模式, 这里用 arm 架构， 指定 THUMB 指令集
    # 2. 将代码片段映射到模拟器的虚拟地址
    ADDRESS = 0x1000 # 映射开始地址
    SIZE = 1024*1024*10  # 分配映射大小(多分一点)
    # 3. 开始映射
    mu.mem_map(ADDRESS, SIZE)  # 初始化映射 参数1：地址 参数2:空间大小  默认初始化后默认值：0
    mu.mem_write(ADDRESS, CODE)  # 写入指令 参数1: 写入位置 参数2:写入内容
    """处理外部 so 调用"""
    # 此处要给，调用了外部 so 的地址写入 nop， 然后通过添加回调函数来实现效果
    mu.mem_write(ADDRESS+0x859A, b'\x00\xbf\x00\xbf')  # \x00\xbf\x00\xbf 为 两个 nop， 因为0x859A处有4个字节，所以用两个nop 填充
    # 写入寄存器
    # 4. 寄存器初始化 指令集涉及到 R0，R1，R2，R3 4个寄存器
    # 第一个参数是 string ，需要给指针、
    mu.mem_map(ADDRESS+SIZE+0x1000, 1024)  # 开辟
    mu.mem_write(ADDRESS+SIZE+0x1000, b'flag2')  # 写入
    bytes=mu.mem_read(ADDRESS+SIZE+0x1000,5)  # 调试输出
    print(binascii.b2a_hex(bytes))
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_R0, ADDRESS+SIZE+0x1000)  # 在 r0 寄存器上写入刚刚创建的指针
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_R1, 0x2)  # 在 r1 寄存器上写入 0x2
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_R2, 0x3)  # 在 r1 寄存器上写入 0x3
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_R3, 0x4)  # 在 r1 寄存器上写入 0x4
    # 但是 IDA 中我们并没有做堆栈平衡处理，要指向一个地址，他才能执行完
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_LR,ADDRESS+0x456)  # 随便指向 0x456 一个存在的地址
    # 5. 初始化堆栈，因为要对内存进行操作 设置 SP
    SP = ADDRESS+SIZE-16  # 多减点，预留 sp 剩下两个参数的位置
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_SP,SP)
    # 6. 多的两个参数，5和 6 要手动放入堆栈当中(从右至左)
    mu.mem_write(SP, struct.pack('I', 5))
    mu.mem_write(SP+4, struct.pack('I', 6))
    # hook 代码
    mu.hook_add(unicorn.UC_HOOK_CODE, hook_code)
    mu.hook_add(unicorn.UC_HOOK_INTR,hook_syscall)  # hook 系统调用函数
    mu.hook_add(unicorn.UC_HOOK_BLOCK,hook_block)  # hook 基本块   
    print_result(mu)  # capstone 输出
    try: 
        add_satrt = ADDRESS+0x854C+1  # 偏移位置 ida 查看 THUMB 指令集所以要 ADDRESS +1,    
        add_end = ADDRESS+0x85D8 # 因为我们手动平衡了内存所以多给点空间
        mu.emu_start(add_satrt, add_end)  # 参数1:起始位置，参数2:结束位置
        print('-------- unicorn 执行后--------')
        print_result(mu)  # capstone 输出
    except unicorn.UcError as e:
        print('\033[1;31mError: %s \033[0m' % e)
def hook_code(mu, address, size, user_data):
    """定义回调函数， 在进入汇编指令之前就会先运行这里
    mu: 模拟器
    address: 执行地址
    size: 汇编指令大小
    user_data: 通过 hook_add 添加的参数
    """
    code=mu.mem_read(address,size)  # 读取
    if address==0x1000+0x859A:  # 外部 so 调用地址
        """hook 两个参数并返回正确值（自行计算）"""
        r0value=readstring(mu,mu.reg_read(unicorn.arm_const.UC_ARM_REG_R0))
        r1value = readstring(mu, mu.reg_read(unicorn.arm_const.UC_ARM_REG_R1))
        index=r0value.find(r1value)  # 用 find 的方法模拟实现并写入 R0 寄存器中即可
        if index==-1:  # 没有找到的话，就返回 0 
            mu.reg_write(unicorn.arm_const.UC_ARM_REG_R0,0)
        else:  # 找到的话，就返回位置
            mu.reg_write(unicorn.arm_const.UC_ARM_REG_R0, index)
        print("\033[1;36m执行外部 so 函数 strstr 参数1: %s, 参数2: %s\033[0m"%(r0value, r1value))
    CP = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)  # 指定 THUMB 指令集
    for i in CP.disasm(code, 0, len(code)):
        print('\033[1;30m【Hook cpu】 地址: 0x%x | 操作码: %s | 内容: %s\033[0m'%(address + i.address, i.mnemonic, i.op_str))
    return 
def hook_syscall(mu,intno,user_data):
    print("\033[1;36mhook 系统调用 系统调用号: 0x%d"%intno)
    if intno==2:  # 例子 2 是退出
        print("系统调用退出!!")
    print_result(mu)
    print("\033[0m")
    return
def hook_block(mu, address, size, user_data):
    # code = mu.mem_read(address,size)
    print("\033[1;36mhook 基本块")
    print_result(mu)
    print("\033[0m")
    return
def print_result(mu):
    """调试寄存器值
    """
    for i in range(66,78):
        print("寄存器[R%d], hex 值:%x"%(i-66,mu.reg_read(i)))
    print("SP 值:%x" % (mu.reg_read(unicorn.arm_const.UC_ARM_REG_SP)))
    print("PC 值:%x" % (mu.reg_read(unicorn.arm_const.UC_ARM_REG_PC)))
def readstring(mu,address):
    """读出结果"""
    result=''
    tmp=mu.mem_read(address,1)
    while(tmp[0]!=0):
        result=result+chr(tmp[0])
        address=address+1
        tmp = mu.mem_read(address, 1)
    return result
if __name__ == "__main__":
    print('\n-------------- add_six 延展外部 so 调用示例--------------')
    capstone_print(CODE, 0x851C)
    uni_add_six()