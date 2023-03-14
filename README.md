## Fixed
    - 修复了QuincyScan结果不输出的问题
    - 修复了QuincyDataExtraction中generateDumps对部分数据库中的样本误判为压缩文件导致不能正常运行
    - 实现了所有features对异常vad节点返回空串的兼容(排除异常vad大小节点)，在binary类部分特征中构建PE对象前增加了if判断，适当提高效率
    - 修复了QuincyLearn中__get_data()函数需要手动注释malfind和hollowfind相关检测代码的问题，实现自动化识别
    - 修改generateDumps模块相关内容，通过2G, 4G测试
    - 将内存转储文件及其压缩文件位置修改为QuincyConfig中用由户可以手动修改
    - 修改QuincyScan部分代码，使其先行判断当前配置是否符合输入模型要求
    - 增加部分注释
    - 修复了QuincyCreateGroundTruth.py中存在的临时目录堆积问题
    - 修复了DigDogReport中网络活动部分因volatility未能获取地址信息导致的查询失败
    - 修复了只有第一份报告折叠的问题
    - 修复了安装脚本的若干问题

## new features
     ~~- 新增netscan模块，QuincyScan中使用参数--with_netscan即可，最终会输出恶意进程的网络活动( **若存在恶意进程且有网络活动** )~~
     - 新增thread_delay_detect模块，用于检测延迟线程情况
     - 新增thread_priority_detect模块，用于检测异常优先级的线程情况
     - 新增process_promote_detect模块，用于检测异常进程提权情况
     - 新增多线程支持，加快DigDogScan的提取特征效率
     - 新增memory类的两个检测特征:memory_vnc, memory_dga_related
     - 新增trojan类的五个检测特征:trojan_currency, trojan_country, trojan_propagation, trojan_redirect, trojan_clipboard
     - 新增注册表自启动项提取模块
     - 新增网络信息提取模块
     - 新增dll信息提取模块
     - 新增内存镜像信息提取模块
     - 新增可疑ip DNS记录功能
     - 将所有输出及界面换为了中文界面，修改UI界面布局，提升使用体验感
     - 新增恶意进程完整命令行信息提取
     - 新增恶意DGA域名对应的恶意软件家族查询
     - 新增恶意进程加载DLL的函数导入表信息
     
## new Module
    - 增加自动测试脚本，完成对原项目模块的划分
    - 增加对应的使用指南
    - 新增DigDogReport模块用于输出报告（报告页面初步完成）
    - 新增DigDog UI模块用于展示UI与操纵DigDog，界面显示为中文
    - 新增自动化依赖安装脚本
    - 网页展示新增产品运行视频与说明