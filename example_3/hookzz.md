# hookZZ-Arm32

# 0.注意事项

unidbg在java层主动调用的so动态/静态注册函数时，不能对对应的native层函数进行hook，会出问题；可以对之后的函数进行hook分析



## 1.hexdump参数 + 打印传入传出参数

## 1.1 hexdump参数

```java
public void hook65540(){
    // 加载HookZz
    IHookZz hookZz = HookZz.getInstance(emulator);

	// enable hook：启用对 ARM 和 ARM64 架构下分支指令（如 B、BL、BX、BLX 等）的 Hook 功能。它对控制程序的执行流、函数调用链的跟踪和调试等场景特别有用。
	hookZz.enable_arm_arm64_b_branch();
	// inline wrap导出函数
	hookZz.wrap(module.base + 0x11140 + 1, new WrapCallback<HookZzArm32RegisterContext>() { 
		@Override
		// 类似于 frida onEnter
		public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
		    // 类似于Frida args[0]
		    Inspector.inspect(ctx.getR0Pointer().getByteArray(0, 0x10), "Arg1");
		    System.out.println(ctx.getR1Long());
		    Inspector.inspect(ctx.getR2Pointer().getByteArray(0, 0x10), "Arg3");
		    // push 
		    ctx.push(ctx.getR2Pointer());
		};
		
		@Override
		// 类似于 frida onLeave
		public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
		    // pop 取出
		    Pointer output = ctx.pop();
		    Inspector.inspect(output.getByteArray(0, 0x10), "Arg3 after function");
		}
	});
	hookZz.disable_arm_arm64_b_branch();
}
```
## 1.2 打印传入传出参数

```java
public void hook_2221C(){
        // 获取HookZz对象
        IHookZz hookZz = HookZz.getInstance(emulator); // 加载HookZz，支持inline hook，文档看https://github.com/jmpews/HookZz
        // enable hook
        hookZz.enable_arm_arm64_b_branch(); // 测试enable_arm_arm64_b_branch，可有可无
        // hook MDStringOld
        hookZz.wrap(module.base + 0x2221C + 1, new WrapCallback<HookZzArm32RegisterContext>() { // inline wrap导出函数
            @Override
            // 方法执行前
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                // 类似于Frida args[0]
                Pointer input = ctx.getPointerArg(0);
                byte[] inputhex = input.getByteArray(0, 20);
                Inspector.inspect(inputhex, "IV");

                Pointer text = ctx.getPointerArg(1);
                byte[] texthex = text.getByteArray(0, 64);
                Inspector.inspect(texthex, "block");
                ctx.push(input);
                ctx.push(text);
            };

            @Override
            // 方法执行后
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer text = ctx.pop();
                Pointer IV = ctx.pop();

                byte[] IVhex = IV.getByteArray(0, 20);
                Inspector.inspect(IVhex, "IV");

                byte[] outputhex = text.getByteArray(0, 64);
                Inspector.inspect(outputhex, "block out");

            }
        });
        hookZz.disable_arm_arm64_b_branch();
    };
```







## 2.提取hexdump中的readPointer，hexdump指定地址

### 2.1 readPointer和hexdump和ptr

```java
int readPointer(int addr){
	UnidbgPointer p = UnidbgPointer.pointer(emulator,addr);
	return p.getInt(0);
}

UnidbgPointer ptr(int addr){
	return UnidbgPointer.pointer(emulator,addr);
}

void hexdump(int addr, int len, String name){
	UnidbgPointer key_addr_ptr = ptr(addr);
	byte[] keyhex = key_addr_ptr.getByteArray(0, len);
	Inspector.inspect(keyhex, name);
}

```

### 2.2 hexdump指定地址

```java
void hook_66666(){
	// 获取HookZz对象
	IHookZz hookZz = HookZz.getInstance(emulator); // 加载HookZz，支持inline hook，文档看https://github.com/jmpews/HookZz
	// enable hook
	// 启用对 ARM 和 ARM64 架构下分支指令（如 B、BL、BX、BLX 等）的 Hook 功能。它对控制程序的执行流、函数调用链的跟踪和调试等场景特别有用。
	hookZz.enable_arm_arm64_b_branch();
	// hook MDStringOld
	hookZz.wrap(module.base + 0x66666 + 1, new WrapCallback<HookZzArm32RegisterContext>() { // inline wrap导出函数
		@Override
		// 方法执行前
		public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
			// 类似于Frida args[1]
			// Pointer input_stru = ctx.getPointerArg(0);
			// byte[] inputhex = input_stru.getByteArray(0, 64);
			// Inspector.inspect(inputhex, "input_stru");




			// FIXME: 2024/8/5   readPointer
			// UnidbgPointer p = UnidbgPointer.pointer(emulator,key_struct);
			// UnidbgPointer p = readPointer(key_struct);
			// int key_struct_len = p.getInt(0);

			// 1. Fixme key结构体
			int key_struct = ctx.getIntArg(0);

			int key_len = readPointer(key_struct);
			System.out.println("key_len:"+key_len);

			int key_addr = readPointer(key_struct+4);
			hexdump(key_addr,key_len,"key:");

			// 2. Fixme iv结构体
			int iv_struct = ctx.getIntArg(1);

			int iv_len = readPointer(iv_struct);
			System.out.println("iv_len:"+iv_len);

			int iv_addr = readPointer(iv_struct+4);
			hexdump(iv_addr,iv_len,"iv:");


			// 3. Fixme 密文结构体
			int encrypt_struct = ctx.getIntArg(2);

			int encrypt_len = readPointer(encrypt_struct);
			System.out.println("encrypt_len:"+encrypt_len);

			int encrypt_addr = readPointer(encrypt_struct+4);
			hexdump(encrypt_addr,encrypt_len,"encrypt:");

		};

		@Override
		// 方法执行后
		public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {


		}
	});
	hookZz.disable_arm_arm64_b_branch();
}
```



# 3.操作入参和返回值

## 3.1  打印返回值

```java
public void HookMDStringold(){
    // 加载HookZz
    IHookZz hookZz = HookZz.getInstance(emulator);

    hookZz.wrap(module.base + 0x1BD0 + 1, new WrapCallback<HookZzArm32RegisterContext>() { // inline wrap导出函数
        @Override
        // 类似于 frida onEnter
        public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
            // 类似于Frida args[0]
            Pointer input = ctx.getPointerArg(0);
            System.out.println("input:" + input.getString(0));
        };

        @Override
        // 类似于 frida onLeave
        public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
            Pointer result = ctx.getPointerArg(0);
            System.out.println("input:" + result.getString(0));
        }
    });
}
```



## 3.2 修改入参和返回值

```java
//unidbg集成了HookZz框架
int address=0x11111;
HookZz hookZz = HookZz.getInstance(emulator);
hookZz.replace(address, new ReplaceCallback() {
      @Override
      public HookStatus onCall(Emulator<?> emulator, long originFunction) {
            return super.onCall(emulator, originFunction);
      }

      @Override
      public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
           //R2和R3才是参数，R0是env，R1是object
           System.out.println(String.format("R2: %d, R3: %d",context.getIntArg(2),context.getIntArg(3)));
           //把第二个参数R3改成5
           emulator.getBackend().reg_write(Unicorn.UC_ARM_REG_R3,5);
           return super.onCall(emulator, context, originFunction);
      }

      @Override
      public void postCall(Emulator<?> emulator, HookContext context) {
            emulator.getBackend().reg_write(Unicorn.UC_ARM_REG_R0,10);
                //返回值放R0，这里直接修改返回值
            super.postCall(emulator, context);
      }
},true);
```



