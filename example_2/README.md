# 1. 说明
## 1.1 修改

对该案例中无法复现的部分进行修复处理

![image](https://github.com/FBLeee/unidbg-anti/assets/50468890/40b9ae2e-5411-44de-87ba-2042f3af6db2)




## 1.2 对单一函数处理

idapython脚本中对整个.text段进行处理，但是时间过长，如果仅需要对单一函数进行处理，可在此处修改起始和结束地址即可

```python
# 遍历该段的所有指令
process_instructions(函数起始地址, 函数结束地址, sub_matches)  
```

![image](https://github.com/FBLeee/unidbg-anti/assets/50468890/f488fb3f-f153-4ab9-b0c5-f1330354c873)



# 2.效果图

![image](https://github.com/FBLeee/unidbg-anti/assets/50468890/d85cde74-9c07-4c4c-8227-bfefa54feb31)

# 致谢
如果此网站不是原创处，联系修改。
https://developer.aliyun.com/article/1330088
