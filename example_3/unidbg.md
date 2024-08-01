# 0.致谢

注：from https://www.52pojie.cn/thread-1902129-1-1.html

# 1.参数构建

```java
// 基本方式
List<Object> args = new ArrayList<>(10);
// 兼容格式
   // 参数1：JNIEnv *env
args.add(vm.getJNIEnv());
   // 参数2：jobject 或 jclass
DvmObject<?> cnative = cNative.newObject(null);
args.add(cnative.hashCode());
   //如果用不到直接填0即可
args.add(0);
   //其他参数-1：字符串对象
String input = "abcdef";
args.add(vm.addLocalObject(new StringObject(vm, input)));
   //其他参数-2：bytes 数组
String str= "abcdef";
byte[] str_bytes = str.getBytes(StandardCharsets.UTF_8);
ByteArray str_bytes _array = new ByteArray(vm,str_bytes );
args.add(vm.addLocalObject(str_bytes _array));
   //其他参数-3：bool
   //false 填 0，true 填 1
args.add(1);
```

# 2. AndroidEmulator 实例

## 2.1 AndroidEmulator 创建

```java
//复制代码 隐藏代码
AndroidEmulator emulator = AndroidEmulatorBuilder
                //指定32位CPU
                .for32Bit() 
                //添加后端，推荐使用Dynarmic，运行速度快，但并不支持某些新特性
                .addBackendFactory(new DynarmicFactory(true)) 
                //指定进程名，推荐以安卓包名做进程名
                .setProcessName("com.github.unidbg")
                //设置根路径
                .setRootDir(new File("target/rootfs/default"))
                //生成AndroidEmulator实例
                .build();
```

```java
AndroidEmulatorBuilder 构造了一个 AndroidEmulator 实例之后，就可以直接来操作这个实例,常使用的一些API
```

## 2.2 AndroidEmulator 常用API

```java
//获取内存操作接口
Memory memory = emulator.getMemory();
//获取进程pid
int pid = emulator.getPid();
//创建虚拟机
VM dalvikVM = emulator.createDalvikVM();
//创建虚拟机并指定APK文件
VM dalvikVM = emulator.createDalvikVM(new File("apk file path"));
//获取已创建的虚拟机
VM dalvikVM = emulator.getDalvikVM();
//显示当前寄存器状态 可指定寄存器
emulator.showRegs();
//获取后端CPU
Backend backend = emulator.getBackend();
//获取进程名
String processName = emulator.getProcessName();
//获取寄存器
RegisterContext context = emulator.getContext();
//Trace读内存
emulator.traceRead(1,0);
//Trace写内润
emulator.traceWrite(1,0);
//Trace汇编
emulator.traceCode(1,0);
//是否正在运行
boolean running = emulator.isRunning();
```

# 3. Memory 实例

```java
Memory memory = emulator.getMemory();
//指定Android SDK 版本，目前支持19和23两个版本
memory.setLibraryResolver(new AndroidResolver(23));

//拿到一个指针，指向内存地址，通过该指针可操作内存
UnidbgPointer pointer = memory.pointer(address);

//获取当前内存映射情况
Collection<MemoryMap> memoryMap = memory.getMemoryMap();

//根据模块名来拿到某个模块
Module module = memory.findModule("module name");

//根据地址拿到某个模块
Module module = memory.findModuleByAddress(address);
```



# 4. VM 操作

```java
//推荐指定APK文件，Unidbg会自动做许多固定的操作
VM vm = emulator.createDalvikVM();

//是否输出JNI运行日志
vm.setVerbose(true);

//加载SO模块 参数二设置是否自动调用init函数
DalvikModule dalvikModule = vm.loadLibrary(new File("so 文件路径"), true);

//设置JNI交互接口 参数需实现Jni接口，推荐使用this继承AbstractJni
vm.setJni(this);

//获取JNIEnv指针，可作为参数传递
Pointer jniEnv = vm.getJNIEnv();

//获取JavaVM指针，可作为参数传递
Pointer javaVM = vm.getJavaVM();

//调用JNI_OnLoad函数
vm.callJNI_OnLoad(emulator,dalvikModule.getModule());

//向VM添加全局对象，返回该对象的hash值
int hash = vm.addGlobalObject(dvmObj);

//获取虚拟机中的对象，参数为该对象的hash值
DvmObject<?> object = vm.getObject(hash);
```

# 5. unidbg hook

hook 代码是逆向最基本的功能之一，frida 的 hook 代码都不陌生，Unidbg 还内置了多种 HOOK 框架，unidbg 底层用的是分析So比较实用的 **HookZz 框架**， hook 的代码的demo

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

# 6.实例

```java
  if ( !input_str )
    return 0;
    //将一个输入的jstring 转化成 UTF8的sting
  input_str_src = (unsigned __int8 *)_JNIEnv::GetStringUTFChars(env, input_str, 0);
    //查找build类，去获得手机相关指纹信息
  clazz = _JNIEnv::FindClass(env, "android/os/Build");
  fieldID = _JNIEnv::GetStaticFieldID(env, clazz, "FINGERPRINT", "Ljava/lang/String;");
  _JNIEnv::GetStaticObjectField(env, clazz, fieldID);
   //对输入的字符串追加REAL 字符
  strcat((char *)input_str_src, "REAL");
    //对拼接后的字符串再进一步处理
  obj = (_jobject *)j_o0OoOOOO(env, input_str_src);
  _android_log_print(4, "roysuejni", "before entering aes => %s", (const char *)input_str_src);
   //引入Java MD5算法
  Class = _JNIEnv::FindClass(env, "java/security/MessageDigest");
  methodID = _JNIEnv::GetStaticMethodID(env, Class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
  method_str = j_o0OoOOOO(env, "MD5");

  v14 = _JNIEnv::CallStaticObjectMethod(env, Class, methodID, method_str);
  v13 = _JNIEnv::GetMethodID(env, Class, "digest", "([B)[B");
  v12 = _JNIEnv::FindClass(env, "java/lang/String");
  v11 = _JNIEnv::GetMethodID(env, v12, "getBytes", "()[B");
  v10 = _JNIEnv::CallObjectMethod(env, obj, v11);
  array = (_jbyteArray *)_JNIEnv::CallObjectMethod(env, v14, v13, v10);
   //最终结果 被ByteArrayElements记录
  ByteArrayElements = _JNIEnv::GetByteArrayElements(env, array, 0);
   //对最终的结果格式化
for ( i = 0; i <= 15; ++i )
    sprintf((char *)&v24[i], "%02x", (unsigned __int8)ByteArrayElements[i]);
    //对输入的字符串加个REAL之后的字符在进行一遍处理
  v23 = (char *)j_ll11l1l1ll(input_str_src);
    //字符拼接到v23中
  strcat(v23, (const char *)v24);
    //获得最终加密结果
  output_str = j_o0OoOOOO(env, (const unsigned __int8 *)v23);
  _android_log_print(4, "roysuejni", "result is => %s ", v23);
    //释放之前的指针资源
  _JNIEnv::ReleaseStringUTFChars(env, input_str, input_str_src);
  free(v23);
  return output_str;
```

