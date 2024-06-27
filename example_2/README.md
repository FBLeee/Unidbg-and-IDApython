# 1. 说明
## 1.1 修改

对该案例中无法复现的部分进行修复处理

![image-20240627171351507](C:\Users\FH\AppData\Roaming\Typora\typora-user-images\image-20240627171351507.png)



## 1.2 对单一函数处理

idapython脚本中对整个.text段进行处理，但是发现时间过长，如果对单一函数进行处理，可在此处修改起始和结束地址即可

```python
# 遍历该段的所有指令
process_instructions(函数起始地址, 函数结束地址, sub_matches)  
```

![image-20240627171552951](C:\Users\FH\AppData\Roaming\Typora\typora-user-images\image-20240627171552951.png)





# 2.效果图

![效果](C:\Users\FH\Downloads\unidbg-anti-8cf264abeb2be7da2b2711da61a3586e0e0835f1\example_2\效果.png)
