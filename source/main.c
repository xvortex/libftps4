/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */
#include "ps4.h"
#include "defines.h"
#include "debug.h"
#include "ftps4.h"
#include "dump.h"

int run;

static void build_iovec(struct iovec** iov, int* iovlen, const char* name, const void* val, size_t len) {
	int i;

	if (*iovlen < 0)
		return;

	i = *iovlen;
	*iov = realloc(*iov, sizeof **iov * (i + 2));
	if (*iov == NULL) {
		*iovlen = -1;
		return;
	}

	(*iov)[i].iov_base = strdup(name);
	(*iov)[i].iov_len = strlen(name) + 1;
	++i;

	(*iov)[i].iov_base = (void*)val;
	if (len == (size_t)-1) {
		if (val != NULL)
			len = strlen(val) + 1;
		else
			len = 0;
	}
	(*iov)[i].iov_len = (int)len;

	*iovlen = ++i;
}

static int mount_large_fs(const char* device, const char* mountpoint, const char* fstype, const char* mode, unsigned int flags) {
	struct iovec* iov = NULL;
	int iovlen = 0;

	build_iovec(&iov, &iovlen, "fstype", fstype, -1);
	build_iovec(&iov, &iovlen, "fspath", mountpoint, -1);
	build_iovec(&iov, &iovlen, "from", device, -1);
	build_iovec(&iov, &iovlen, "large", "yes", -1);
	build_iovec(&iov, &iovlen, "timezone", "static", -1);
	build_iovec(&iov, &iovlen, "async", "", -1);
	build_iovec(&iov, &iovlen, "ignoreacl", "", -1);

	if (mode) {
		build_iovec(&iov, &iovlen, "dirmask", mode, -1);
		build_iovec(&iov, &iovlen, "mask", mode, -1);
	}

	return nmount(iov, iovlen, flags);
}

void custom_MTRW(ftps4_client_info_t *client)
{
	if (mount_large_fs("/dev/da0x0.crypt", "/preinst",   "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	if (mount_large_fs("/dev/da0x1.crypt", "/preinst2",  "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	if (mount_large_fs("/dev/da0x4.crypt", "/system",    "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	if (mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_UPDATE) < 0) goto fail;

	ftps4_ext_client_send_ctrl_msg(client, "200 Mount success." FTPS4_EOL);
	return;

fail:
	ftps4_ext_client_send_ctrl_msg(client, "550 Could not mount!" FTPS4_EOL);
}

void custom_SHUTDOWN(ftps4_client_info_t *client) {
	ftps4_ext_client_send_ctrl_msg(client, "200 Shutting down..." FTPS4_EOL);
	run = 0;
}

unsigned int long long __readmsr(unsigned long __register) {
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}

struct auditinfo_addr {
    char useless[184];
};

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};

struct thread {
    	void *useless;
    	struct proc *td_proc;
};

#define	KERN_XFAST_SYSCALL	0x1C0		// 5.01
#define KERN_PRISON_0		0x10986A0
#define KERN_ROOTVNODE		0x22C19F0

int kpayload(struct thread *td){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[KERN_PRISON_0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug settings patches 5.01
	*(char *)(kernel_base + 0x1CD0686) |= 0x14;
	*(char *)(kernel_base + 0x1CD06A9) |= 3;
	*(char *)(kernel_base + 0x1CD06AA) |= 1;
	*(char *)(kernel_base + 0x1CD06C8) |= 1;

	// debug menu error patches 5.01
	*(uint32_t *)(kernel_base + 0x4F8C78) = 0;
	*(uint32_t *)(kernel_base + 0x4F9D8C) = 0;

	// target_id patches 5.01
	*(uint16_t *)(kernel_base + 0x1CD068C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x236B7FC) = 0x8101;

	// enable mmap of all SELF 5.01
	*(uint8_t*)(kernel_base + 0x117B0) = 0xB0;
	*(uint8_t*)(kernel_base + 0x117B1) = 0x01;
	*(uint8_t*)(kernel_base + 0x117B2) = 0xC3;

	*(uint8_t*)(kernel_base + 0x117C0) = 0xB0;
	*(uint8_t*)(kernel_base + 0x117C1) = 0x01;
	*(uint8_t*)(kernel_base + 0x117C2) = 0xC3;

	*(uint8_t*)(kernel_base + 0x13EF2F) = 0x31;
	*(uint8_t*)(kernel_base + 0x13EF30) = 0xC0;
	*(uint8_t*)(kernel_base + 0x13EF31) = 0x90;
	*(uint8_t*)(kernel_base + 0x13EF32) = 0x90;
	*(uint8_t*)(kernel_base + 0x13EF33) = 0x90;

	// Restore write protection
	writeCr0(cr0);

	return 0;
}

int get_ip_address(char *ip_address)
{
	int ret;
	SceNetCtlInfo info;

	ret = sceNetCtlInit();
	if (ret < 0)
		goto error;

	ret = sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, &info);
	if (ret < 0)
		goto error;

	memcpy(ip_address, info.ip_address, sizeof(info.ip_address));

	sceNetCtlTerm();

	return ret;

error:
	ip_address = NULL;
	return -1;
}

int _main(struct thread *td)
{
	char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char msg[64];

	run = 1;

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

#ifdef DEBUG_SOCKET
	initDebugSocket();
#endif

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	syscall(11,kpayload,td);

	initSysUtil();
	notify("Welcome to FTPS4 v"VERSION);

	int ret = get_ip_address(ip_address);
	if (ret < 0)
	{
		notify("Unable to get IP address");
		goto error;
	}

	ftps4_init(ip_address, FTP_PORT);
	ftps4_ext_add_custom_command("SHUTDOWN", custom_SHUTDOWN);
	ftps4_ext_add_custom_command("MTRW", custom_MTRW);

	sprintf(msg, "PS4 listening on\nIP %s Port %i", ip_address, FTP_PORT);
	notify(msg);

	while (run) {
		sceKernelUsleep(5 * 1000);
	}

	ftps4_fini();

error:
	notify("Bye!");

#ifdef DEBUG_SOCKET
	closeDebugSocket();
#endif
	return 0;
}
