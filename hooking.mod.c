#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x32e21920, "module_layout" },
	{ 0xe2c7e7f, "sock_release" },
	{ 0x968100e0, "__netlink_kernel_create" },
	{ 0xb014a89f, "init_net" },
	{ 0xa5a1793e, "unregister_ftrace_function" },
	{ 0x837b7b09, "__dynamic_pr_debug" },
	{ 0x90de72a9, "register_ftrace_function" },
	{ 0x6f935e35, "ftrace_set_filter_ip" },
	{ 0x9568a8f0, "dentry_path_raw" },
	{ 0xb3378a7b, "pv_ops" },
	{ 0x30b5ba97, "path_get" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0x833daaa7, "netlink_unicast" },
	{ 0xff6f0dab, "__nlmsg_put" },
	{ 0xe7a13e00, "__alloc_skb" },
	{ 0x19dd88aa, "send_sig_info" },
	{ 0x92997ed8, "_printk" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xa7bfbf2f, "current_task" },
	{ 0x37a0cba, "kfree" },
	{ 0x8522d6bc, "strncpy_from_user" },
	{ 0xf35141b2, "kmem_cache_alloc_trace" },
	{ 0x26087692, "kmalloc_caches" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "04433D0FC35CEBC29C21CEF");
