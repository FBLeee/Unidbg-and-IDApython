# 1.获取SO基地址

## 1.1 frida 获取基地址

```javascript
var baseAddr = Module.findBaseAddress("libnative-lib.so");
```

## 1.2 Unidbg 获取基地址

```java
// 加载so到虚拟内存
DalvikModule dm = vm.loadLibrary("libnative-lib.so", true);
// 加载好的so对应为一个模块
module = dm.getModule();
// 打印libnative-lib.so在Unidbg虚拟内存中的基地址
System.out.println("baseAddr:"+module.base);
```

### 1.2.1 加载了多个SO的情况

```java
// 获取某个具体SO的句柄
Module yourModule = emulator.getMemory().findModule("yourModuleName");
// 打印其基地址
System.out.println("baseAddr:"+yourModule.base);
```

如果只主动加载一个SO，其基址恒为0x40000000 ,这是一个检测Unidbg的点，可以在 com/github/unidbg/memory/Memory.java 中做修改

```java
public interface Memory extends IO, Loader, StackMemory {

    long STACK_BASE = 0xc0000000L;
    int STACK_SIZE_OF_PAGE = 256; // 1024k

    // 修改内存映射的起始地址
    long MMAP_BASE = 0x40000000L;

    UnidbgPointer allocateStack(int size);
    UnidbgPointer pointer(long address);
    void setStackPoint(long sp);
```

# 2.获取函数地址

## 2.1 获取导出函数地址

### 2.1.1 Frida 获取导出函数地址

```javascript
Module.findExportByName("libc.so", "strcmp")
```

### 2.1.2 Unidbg 获取导出函数地址

```java
// 加载so到虚拟内存
DalvikModule dm = vm.loadLibrary("libnative-lib.so", true);
// 加载好的 libscmain.so对应为一个模块
module = dm.getModule();
int address = (int) module.findSymbolByName("funcName").getAddress();
```

## 2.2 获取非导出函数地址

### 2.2.1 Frida 获取非导出函数地址

```javascript
var soAddr = Module.findBaseAddress("libnative-lib.so");
var FuncAddr = soAddr.add(0x1768 + 1);
```

### 2.2.2 Unidbg 获取非导出函数地址

```java
// 加载so到虚拟内存
DalvikModule dm = vm.loadLibrary("libnative-lib.so", true);
// 加载好的so对应为一个模块
module = dm.getModule();
// offset，在IDA中查看
int offset = 0x1768;
// 真实地址 = baseAddr + offset
int address = (int) (module.base + offset);
```

# 3.寄存器

## 3.1获取寄存器的值

### 3.1.1 frida读寄存器的值

```javascript
function hook_native() {
    var base_xxx = Module.findBaseAddress("libxxxx.so")
    Interceptor.attach(base_xxx.add(0x53000), {
        onEnter: function (args) {
            var x10 = this.context.x10;
            var x29 = this.context.x29;
            var x17 = this.context.x17;
            var x9 = this.context.x9;
            console.log(x10, x29, x17, x9)
            
        }, onLeave: function (retval) {
        }
    })
}
```

### 3.1.2 unidbg读寄存器的值

```java
public void HookByConsoleDebugger() {
    Debugger debugger = emulator.attach();
    debugger.addBreakPoint(module.base+0x53A00,new BreakPointCallback(){
        int num = 0;
        @Override
        public boolean onHit(Emulator<?> emulator, long address) {

           // 读取寄存器的值 32位
            // Number r0value=emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_R0); 
            
            // 64位    方法一：    
            Number r0value=emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W17);
            System.out.printf("------------------:0x%02x\n",r0value.intValue());   
            
            // 64位    方法二：
            RegisterContext context = emulator.getContext();
            int x1 = context.getIntByReg(Arm64Const.UC_ARM64_REG_X1);
            System.out.println("A2:0x"+Integer.toHexString(w17)); 
           
            return true;
        }
    });
}
```

## 3.2 hexdump

### 3.2.1 frida---hexdump

```javascript
function hook_native() {
    Interceptor.attach(base_xxxx.add(0x2D89E).add(1), {
            onEnter: function (args) {
                this.a1 = args[0]
                this.a = (this.a1.readPointer());

    
    
                console.log(hexdump(args[1], { length: 1028 }))
    
            },
            onLeave: function (retval) {
    
               
    
            }
     })
}
```

### 3.2.2 unidbg---hexdump

```java
public void HookByConsoleDebugger() {
    Debugger debugger = emulator.attach();
    debugger.addBreakPoint(module.base+0x53123,new BreakPointCallback(){
        int num = 0;
        @Override
        public boolean onHit(Emulator<?> emulator, long address) {

            RegisterContext context = emulator.getContext();
            //第num次进入hook函数内部
            num+=1;
            
            //打印hexdump寄存器的值
                  // 获取 x1 寄存器存储的地址值
             long x1 = context.getLongByReg(Arm64Const.UC_ARM64_REG_X17);
                 //获取x1.readPointer()
             Pointer x1_ptr = memory.pointer(x1);
                  //hexdump
             Inspector.inspect(x1_ptr.getByteArray(0, 64), "MD5Transform input分块_" + num);

            return true;
        }
    });
}
```

```java
public void HookByConsoleDebugger() {
    Debugger debugger = emulator.attach();
    debugger.addBreakPoint(module.base+0x53123,new BreakPointCallback(){
        int num = 0;
        @Override
        public boolean onHit(Emulator<?> emulator, long address) {

            RegisterContext context = emulator.getContext();
            //第num次进入hook函数内部
            num+=1;
            
            //打印hexdump寄存器的值
                  // 获取 x1 寄存器存储的地址值
             long x1 = context.getLongByReg(Arm64Const.UC_ARM64_REG_X17);
                 //获取x1.readPointer()
             Pointer x1_ptr = memory.pointer(x1);
                  //hexdump
             Inspector.inspect(x1_ptr.getByteArray(0, 64), "MD5Transform input分块_" + num);

            return true;
        }
    });
}
```

# 4. 解引用

## 4.1 frida---readPointer

```javascript
function hook_native() {
    Interceptor.attach(base_xxxx.add(0x2D666).add(1), {
            onEnter: function (args) {
                this.a1 = args[0]
                this.a = (this.a1.readPointer());

    
    
                console.log(hexdump(this.a, { length: 256 }))
    
            },
            onLeave: function (retval) {
    
               
    
            }
     })
}
```

## 4.2 unidbg---readPointer

```java
public void HookByConsoleDebugger() {
    Debugger debugger = emulator.attach();
    debugger.addBreakPoint(module.base+0x53xxx,new BreakPointCallback(){
        int num = 0;
        @Override
        public boolean onHit(Emulator<?> emulator, long address) {

            RegisterContext context = emulator.getContext();
            //第num次进入hook函数内部
            num+=1;

            //打印hexdump寄存器的值
            // 获取 x1 寄存器存储的地址值
            int x1 = context.getIntByReg(Arm64Const.UC_ARM64_REG_X1);
            System.out.printf("x1:0x%02x\n",x1);
            //获取x1.readPointer()
            Pointer x1_ptr = memory.pointer(x1);
            System.out.println("x1_ptr:"+x1_ptr);
            // hexdump
            Inspector.inspect(x1_ptr.getByteArray(0, 64), "MD5Transform input分块_" + num);

            return true;
        }
    });
}
```

# 5. 读字符串

## 5.1 frida---readCString

```javascript
function hook_native() {
    Interceptor.attach(base_xxx.add(0x2D111).add(1), {
            onEnter: function (args) {
                this.a1 = args[0]
                this.a_str = (this.a1.readCString());
                console.log(this.a_str)
            },
            onLeave: function (retval) {

            }
     })
}
```

## 5.2 unidbg---readCString

```java
public void HookByConsoleDebugger(){
    int targetAddr = module.base+0x53000
    emulator.attach().addBreakPoint(targetAddr, new BreakPointCallback() {
        @Override
        public boolean onHit(Emulator<?> emulator, long address) {
            RegisterContext context = emulator.getContext();
                //Pointer input = context.getPointerArg(0);
                //int length = context.getIntArg(1);
            Pointer buffer = context.getPointerArg(2);
            //hexdump(buffer)
            Inspector.inspect(buffer.getByteArray(0, length), "base64 input");
            
            
            // OnLeave
            emulator.attach().addBreakPoint(context.getLRPointer().peer, new BreakPointCallback() {
                @Override
                public boolean onHit(Emulator<?> emulator, long address) {
                    //buffer.readCString()
                    String result = buffer.getString(0);
                    System.out.println("base64 result:"+result);
                    return true;
                }
            });
            return true;
        }
    });
}
```

```java
public String calculateS() {
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // arg1,env
        list.add(0); // arg2,jobject
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        list.add(vm.addGlobalObject(context));
        list.add(vm.addLocalObject(new StringObject(vm, "135691695686123456789")));
        list.add(vm.addLocalObject(new StringObject(vm, "CypCHG2kSlRkdvr2RG1QF8b2lCWXl7k7")));
        //主动调用返回值为字符串
        Number number = module.callFunction(emulator, 0x1E7C + 1, list.toArray());
 
        String result = vm.getObject(number.intValue()).getValue().toString();
        return result;
    }
```

# 6.主动调用

## 6.1 frida主动调用

```javascript
function call_var() {
  Java.perform(function () {
    var FridaActivity2 = Java.use("com.github.androiddemo.Activity.FridaActivity2");
    console.log("static_bool_var:", FridaActivity2.static_bool_var.value);
    //调用静态函数
    FridaActivity2.setStatic_bool_var();  
    console.log("static_bool_var:", FridaActivity2.static_bool_var.value);

    //调用非静态函数
    Java.choose("com.github.androiddemo.Activity.FridaActivity2", {
      onMatch : function(instance) {
        console.log("bool_var:", instance.bool_var.value);
        instance.setBool_var();
        console.log("bool_var:", instance.bool_var.value);
      }, onComplete : function() {
      }
    })
  });
}
```

## 6.2 unidbg主动调用

```java
// 模拟内部C语言逻辑
    public int call_getstriniglength(){

        //构建字符串参数传入
        String input = "hello";
        // 申请内存空间
        MemoryBlock block1=emulator.getMemory().malloc(input.length()+1,false);
        // 获取该内存空间的指针
        UnidbgPointer str1_ptr=block1.getPointer();
        // 把字符串变成byte数组作为参数传入
        str1_ptr.write(input.getBytes());
        // print指针所指的内存数据
        Inspector.inspect(str1_ptr.getByteArray(0, input.length()), "input");
        System.out.println("输入字符串为：" + str1_ptr.getString(0));
        
        
        // 主动调用 方法一：直接传入
        // Number result=module.callFunction(emulator,0xA26+ 1,(str1_ptr));

        // 主动调用 方法二：传入参数列表
        List<Object> list = new ArrayList<>(10);
        list.add(str1_ptr);
        Number result=module.callFunction(emulator,0xA26+ 1,list.toArray());
        
        
        
        // 读取寄存器的值
        // Number r0value=emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_R0);
        
        // 返回字符串
        // String result_str = vm.getObject(result.intValue()).getValue().toString();
        // System.out.println("result:"+result_str);
        // return result_str;

        // 返回int
        return result.intValue();
    }

```

# 7.patch

## 7.1 frida

### 7.1.1  代码patch

```javascript
function nop(addr) {
    Memory.patchCode(ptr(addr), 4, code => {
        const cw = new ThumbWriter(code, { pc: ptr(addr) });
        cw.putNop();
        cw.putNop();
        cw.flush();
    });
}


function bypass() {
    let module = Process.findModuleByName("libmsaoaidsec.so");
    // pthread_create函数地址
    nop(module.base.add(0x10AE4))
    nop(module.base.add(0x113F8))
}




function local_init() {
    Interceptor.attach(Module.findExportByName(null, "__system_property_get"),
        {
            onEnter: function (args) {
                var name = args[0];
                if (name !== undefined && name != null) {
                    name = ptr(name).readCString();
                    if (name.indexOf("ro.build.version.sdk") >= 0) {
                        // 这是.init_proc刚开始执行的地方，是一个比较早的hook点
                        // hook代码
                        // todo 查看反调试so库中的pthread_create回调函数的地址
                        // hook_pthread_create()
                        bypass()
                    }
                }
            }
        });

}
```

### 7.1.2 指令patch

```javascript
function nop(targetModule, addr) {
    // 定义要 NOP 的函数地址和指令长度
    var targetFunctionAddress = targetModule.base.add(addr); // 0x1A858 是函数的偏移地址
    var instructionLength = 4; // 假设函数中的指令长度为 4 字节
    
    // 在目标函数地址写入 NOP 指令
    Memory.protect(targetFunctionAddress, instructionLength, 'rwx');
    for (var i = 0; i < instructionLength; i++) {
        Memory.writeU8(targetFunctionAddress.add(i), 0x90); // 0x90 是 NOP 指令
    }
    console.log('NOPed function at address 0x', (addr).toString(16));
}
function hook_libc_getpid() {
    // 寻找并 hook 目标库
    var f = false
    var libcModule = Process.findModuleByName('libc.so');
    if (libcModule) {
        var getpid = libcModule.findExportByName('getpid');
        Interceptor.attach(getpid, {
            onEnter: function (args) {
                var targetModule = Process.getModuleByName('libmsaoaidsec.so');
                if (targetModule && !f) {
                    nop(targetModule, 0x1A858)
                    nop(targetModule, 0x1B8B4)
                    f = true
                }
            },
            onLeave: function (retval) {
            }
        });
    }
}

function hook_pthread_createx() {
    var libcModule = Process.findModuleByName('libc.so');
    if (libcModule) {
        var pthread_create = new NativeFunction(
            libcModule.findExportByName('pthread_create'),
            'int', ['pointer', 'pointer', 'pointer', 'pointer']
        );
        Interceptor.attach(pthread_create, {
            onEnter: function (args) {
                var libmsaoaidsecModule = Process.findModuleByName('libmsaoaidsec.so');
                if (libmsaoaidsecModule) {
                    // 在进入 pthread_create 之前
                    console.log("pthread_create called with arguments:");
                    console.log("attr:", args[0]);
                    console.log("attr:", (args[0] - libmsaoaidsecModule.base).toString(16));
                    console.log("start_routine:", args[1]);
                    console.log("arg:", args[2]);
                    console.log("function at=>0x"+(args[2] - libmsaoaidsecModule.base).toString(16));
                    console.log("pid:", args[3]);
                    console.log('----------------------------------------\n')
                }
            },
            onLeave: function (retval) {
                // 在离开 pthread_create 之后
                console.log("pthread_create returned:", retval);
                if (retval.toInt32() === 0) {
                    console.log("Thread created successfully!");
                } else {
                    console.log("Thread creation failed!");
                }
            }
        });
    }
}


function hook_dlopen1(soName = 'libmsaoaidsec.so') {
    // hook_RegisterNatives()
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        // hook_pthread_createx()
                        hook_libc_getpid()
                    }
                }
            }
        }
    );
}

setImmediate(hook_dlopen1, "libmsaoaidsec.so")

```

## 7.2 unidbg

### 方法一 给出替换机器码

```java
public void patchverfify(){
        int patchCode = 0x4FF00100;
        emulator.getMemory().pointer(module.base+0x1E86).setInt(0,patchCode);
    }
```

### 方法二 给出替换指令

```java
public void patchVerify1(){
        Pointer pointer = UnidbgPointer.pointer(emulator, module.base + 0x1E86);
        assert pointer != null;
        byte[] code = pointer.getByteArray(0, 4);
        if (!Arrays.equals(code, new byte[]{ (byte)0xFF, (byte) 0xF7, (byte) 0xEB, (byte) 0xFE })) { // BL sub_1C60
            throw new IllegalStateException(Inspector.inspectString(code, "patch32 code=" + Arrays.toString(code)));
        }
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb)) {
            KeystoneEncoded encoded = keystone.assemble("mov r0,1");
            byte[] patch = encoded.getMachineCode();
            if (patch.length != code.length) {
                throw new IllegalStateException(Inspector.inspectString(patch, "patch32 length=" + patch.length));
            }
            pointer.write(0, patch, 0, patch.length);
        }
    }
```

