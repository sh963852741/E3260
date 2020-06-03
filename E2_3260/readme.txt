实验要求：
利用VMware虚拟机进行双机互联，实现双人聊天。

step1 虚拟机的安装与配置
VMware快速下载地址

http://down-ww3.7down.net/pcdown/soft/xiazai/vmware-pro15.zip

下载好Windows XP的iso文件 

安装程序光盘映像文件 然后一步步按说明安装

安装vs2010

全部安装好后，将这台虚拟机克隆

->两台虚拟机配置完成！

step2 虚拟机设置
此时需要虚拟机为关机状态

虚拟机->虚拟机设置->添加->串行端口

！！千万注意在硬件设备中删除打印机！！

！！打印机占了端口COM1！！
step3 实验
建议使用.Net Framework 的 System.IO.Ports.SerialPort 类进行开发。

详见：https://msdn.microsoft.com/zh-cn/library/system.io.ports.serialport

对示例代码进行补充与改进。