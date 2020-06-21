此文档对该路径下的文件进行说明。

angr-scripts文件夹:该文件夹里的文件都需要放入angr模块的源码文件夹内，在deepin系统的具体路径为/usr/local/lib/python3.6/dist-packages/angr/analyses
	
	reassembler.py：angr的二次汇编框架关键源码
	
	instructionTest.py：通过在angr的二次汇编框架源码中添加接口，调用该py文件的函数实现ROP攻击防御。
	
	utils.py

ropdefense文件夹：
	
	test_ramblr.py：用于调用二次汇编模块的主文件。
	
	asm2hex_att.py：测试文件，用于测试att格式的汇编文件编译
	
	asm2hex_intel.py：测试文件，用于测试intel格式的汇编文件编译
	
	checksec.sh：用于获取可执行文件的保护方式，由test_ramblr.py调用。

test_binaries文件夹：用于测试的可执行文件，无后缀的文件为原文件，后缀为_new的文件为仅经过二次汇编框架产生的文件，后缀为_rop的文件为经过ROP攻击防御的文件

