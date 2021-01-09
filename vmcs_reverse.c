/*
 *  Copyright (C) 2020 Yuma Ueda
 *
 *  Author: Yuma Ueda <cyan@0x00a1e9.dev>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <asm/msr-index.h>
#include <asm/tlbflush.h>
#include <asm/vmx.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <uapi/asm/processor-flags.h>


#define FIRST_METHOD
//#define SECOND_METHOD

#define MINOR_BASE                     0x0
#define MINOR_N                        0x1
#define DEVICE_NAME                    "vmcs_reverse"
#define BUF_LEN                        0x10000


#define CPUID1_ECX_VMX_MASK            (1<<5)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
#define MSR_IA32_FEAT_CTL              MSR_IA32_FEATURE_CONTROL
#define FEAT_CTL_LOCKED                FEATURE_CONTROL_LOCKED
#define FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX \
    FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX
#endif

#define CONST_16                      0x9988
#define CONST_32                      0xBBAA9988
#define CONST_64                      0xFFEEDDCCBBAA9988

#define VMCS_DATA_OFFSET               0x8

#define FIELDS_16_NUM                  (3+10+7)
#define FIELDS_64_NUM                  (27+12+4)
#define FIELDS_64_RO_NUM               1
#define FIELDS_32_NUM                  (18+23+1)
#define FIELDS_32_RO_NUM               8
#define FIELDS_NATURAL_NUM             (8+23+15)
#define FIELDS_NATURAL_RO_NUM          6

// VMCS encodings
#define EPTP_INDEX                     0x0004
#define EXECUTIVE_VMCS_POINTER         0x200C
#define VIRT_EXCEPTION_INFO_ADDR       0x202a
#define SUB_PAGE_PERM_TABLE_POINTER    0x2030
#define ENCLV_EXITING_BITMAP           0x2036
#define GUEST_IA32_PKRS                0x2818
#define HOST_IA32_PKRS                 0x2c06

// 32-bit guest-state fields
#define GUEST_SMBASE                   0x4828

// natural-width guest-state
#define GUEST_IA32_S_CET               0x6828
#define GUEST_SSP                      0x682a
#define GUEST_IA32_INTR_SSP_TABLE_ADDR 0x682c

// natural-width host-state
#define HOST_IA32_S_CET                0x6c18
#define HOST_SSP                       0x6c1a
#define HOST_IA32_INTR_SSP_TABLE_ADDR  0x6c1c


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuma Ueda");
MODULE_DESCRIPTION("LKM designed to dump the VMCS layout");


static int use_counter;
static char msg_buf[BUF_LEN];
static char *rptr_msg_buf;
static char *wptr_msg_buf_init;


static unsigned long fields_16[FIELDS_16_NUM] = {
    // 16-bit control fields
    0x00000000, 0x00000002, EPTP_INDEX,
    // 16-bit guest-state fields
    0x00000800, 0x00000802, 0x00000804, 0x00000806, 0x00000808, 0x0000080a,
    0x0000080c, 0x0000080e, 0x00000810, 0x00000812,
    // 16-bit host-state fields
    0x00000c00, 0x00000c02, 0x00000c04, 0x00000c06, 0x00000c08, 0x00000c0a,
    0x00000c0c
};

static unsigned long fields_64[FIELDS_64_NUM] = {
    // 64-bit control fields
    0x00002000, 0x00002002, 0x00002004, 0x00002006, 0x00002008, 0x0000200a,
    EXECUTIVE_VMCS_POINTER, 0x0000200e, 0x00002010, 0x00002012, 0x00002014,
    0x00002016,
    0x00002018, 0x0000201a, 0x0000201c, 0x0000201e, 0x00002020, 0x00002022,
    0x00002024, 0x00002026, 0x00002028, VIRT_EXCEPTION_INFO_ADDR, 0x0000202C,
    0x0000202E,
    SUB_PAGE_PERM_TABLE_POINTER, 0x00002032, ENCLV_EXITING_BITMAP,
    // 64-bit guest-state fields
    0x00002800, 0x00002802, 0x00002804, 0x00002806, 0x00002808, 0x0000280a,
    0x0000280c, 0x0000280e, 0x00002810, 0x00002812, 0x00002814, GUEST_IA32_PKRS,
    // 64-bit host-state fields
    0x00002c00, 0x00002c02, 0x00002c04, HOST_IA32_PKRS
};

/*
static unsigned long fields_64_ro[FIELDS_64_RO_NUM] = {
    // 64-bit read-only data field
    0x00002400
};
*/

static unsigned long fields_32[FIELDS_32_NUM] = {
    // 32-bit control fields
    0x00004000, 0x00004002, 0x00004004, 0x00004006, 0x00004008, 0x0000400a,
    0x0000400c, 0x0000400e, 0x00004010, 0x00004012, 0x00004014, 0x00004016,
    0x00004018, 0x0000401a, 0x0000401c, 0x0000401e, 0x00004020, 0x00004022,
    // 32-bit guest-state fields
    0x00004800, 0x00004802, 0x00004804, 0x00004806, 0x00004808, 0x0000480a,
    0x0000480c, 0x0000480e, 0x00004810, 0x00004812, 0x00004814, 0x00004816,
    0x00004818, 0x0000481a, 0x0000481c, 0x0000481e, 0x00004820, 0x00004822,
    0x00004824, 0X00004826, GUEST_SMBASE, 0x0000482a, 0x0000482e,
    // 32-bit host-state field
    0x00004c00
};

/*
static unsigned long fields_32_ro[FIELDS_32_RO_NUM] = {
    // 32-bit read-only data fields
    0x00004400, 0x00004402, 0x00004404, 0x00004406, 0x00004408, 0x0000440a,
    0x0000440c, 0x0000440e
};
*/

static unsigned long fields_natural[FIELDS_NATURAL_NUM] = {
    // natural-width control fields
    0x00006000, 0x00006002, 0x00006004, 0x00006006, 0x00006008, 0x0000600a,
    0x0000600c, 0x0000600e,
    // natural-width guest-state field
    0x00006800, 0x00006802, 0x00006804, 0x00006806, 0x00006808, 0x0000680a,
    0x0000680c, 0x0000680e, 0x00006810, 0x00006812, 0x00006814, 0x00006816,
    0x00006818, 0x0000681a, 0x0000681c, 0x0000681e, 0x00006820, 0x00006822,
    0x00006824,
    0x00006826,
    GUEST_IA32_S_CET, GUEST_SSP,
    GUEST_IA32_INTR_SSP_TABLE_ADDR,
    // natural-width host-state fields
    0x00006c00, 0x00006c02, 0x00006c04, 0x00006c06, 0x00006c08, 0x00006c0a,
    0x00006c0c, 0x00006c0e, 0x00006c10, 0x00006c12, 0x00006c14, 0x00006c16,
    HOST_IA32_S_CET, HOST_SSP, HOST_IA32_INTR_SSP_TABLE_ADDR
};

/*
static unsigned long fields_natural_ro[FIELDS_NATURAL_RO_NUM] = {
    // natural-wdith read-only data field
    0x00006400, 0x00006402, 0x00006404, 0x00006406, 0x00006408, 0x0000640a
};
*/

static unsigned long *vmcs_region;
static unsigned long *vmxon_region;


int my_open(struct inode*, struct file*);
ssize_t my_read(struct file*, char __user *, size_t, loff_t*);
int my_release(struct inode*, struct file*);

static dev_t my_devt;
static struct class *my_class;
static struct cdev my_cdev;
static const struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .read = my_read,
    .release = my_release,
};


int my_open(struct inode *inode, struct file *fp)
{
    if (use_counter++)
        return -EBUSY;
    try_module_get(THIS_MODULE);
    rptr_msg_buf = msg_buf;
    return 0;
}

ssize_t my_read(struct file *fp, char __user *buf, size_t count, loff_t *off)
{
    int read_count = count;

    if (rptr_msg_buf == NULL) {
        printk(KERN_ERR "%s: rptr_msg_buf invalid pointer %p\n",
            DEVICE_NAME, rptr_msg_buf);
        goto end;
    }
    if (*rptr_msg_buf==0 || count==0 || *off>=BUF_LEN)
        goto end;

    while (rptr_msg_buf && *rptr_msg_buf && count--)
        put_user(*rptr_msg_buf++, buf++);

    return read_count -= count;

end:
    return 0;
}

int my_release(struct inode* inode, struct file *fp)
{
    use_counter--;
    module_put(THIS_MODULE);
    return 0;
}


static inline int __init vmxoff(void)
{
    asm volatile goto (
        "vmxoff\n\t"
        ".byte 0x3e\n\t"                   // branch taken
        "ja %l[end]\n\t"                   // CF==0 && ZF==0
        "je %l[fail_valid]\n\t"            // ZF==1
        :
        :
        : "cc"
        : fail_invalid, fail_valid, end);  // Add fail_invalid to GotoLabels to
                                           // supress the unused labels warning

fail_invalid:
    printk(KERN_ERR "%s: VMXOFF VMfailInvalid\n", DEVICE_NAME);
    return -EINVAL;

fail_valid:
    printk(KERN_ERR "%s: VMXOFF under \
        dual-monitor treatment of SMIs and SMM\n", DEVICE_NAME);
    return -EPERM;

end:
    return 0;
}

static inline int __init vmread(unsigned long field, unsigned long *buf)
{
    unsigned int error = 0;
    u64 flags64;

    asm volatile (
        "   vmread %3, %0\n\t"
        "   .byte 0x3e\n\t"       // branch taken
        "   ja end%=\n\t"         // CF==0 && ZF==0
        "   je fail_valid%=\n\t"  // ZF==1
        "fail_invalid%=:\n\t"
        "   movl $1, %1\n\t"
        "   jmp end%=\n\t"
        "fail_valid%=:\n\t"
        "   movl $2, %1\n\t"
        "end%=:"
        : "=rm" (*buf), "=rm" (error), "=rm" (flags64)
        : "r" (field)
        : "cc", "memory");

    if (error == 1) {
        printk(KERN_ERR "%s: VMREAD VMfailInvalid %#010lx\n",
                DEVICE_NAME, field);
        return -EINVAL;
    } else if (error == 2) {
        printk(KERN_ERR "%s: VMREAD from unsupported VMCS component %#010lx\n",
                DEVICE_NAME, field);
        return -ENOTSUPP;
    } else {
        return 0;
    }
}

static int __init get_vm_instruction_error(unsigned long *buf)
{
    return vmread(VM_INSTRUCTION_ERROR, buf);
}

static inline int __init vmwrite(unsigned long field, const unsigned long *buf)
{
    unsigned long error;

    asm volatile goto (
        "vmwrite %1, %0\n\t"
        ".byte 0x3e\n\t"                   // branch taken
        "ja %l[end]\n\t"                   // CF==0 && ZF==0
        "je %l[fail_valid]\n\t"            // ZF==1
        :
        : "r"(field), "r"(*buf)
        : "cc", "memory"
        : fail_invalid, fail_valid, end);  // Add fail_invalid to GotoLabels to
                                           // supress the unused labels warning

fail_invalid:
    printk(KERN_ERR "%s: VMXWRITE VMfailInvalid\n", DEVICE_NAME);
    return -EINVAL;

fail_valid:
    get_vm_instruction_error(&error);
    if (error == VMXERR_UNSUPPORTED_VMCS_COMPONENT)
        printk(KERN_ERR
                "%s: VMWRITE to unsupported VMCS component\n", DEVICE_NAME);
    else  // error == VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT
        printk(KERN_ERR
                "%s: VMWRITE to read-only VMCS component\n", DEVICE_NAME);
    return -ENOTSUPP;

end:
    return 0;
}

static inline int __init vmclear(u64 pa)
{
    unsigned long error;

    asm volatile goto (
        "vmclear %0\n\t"
        ".byte 0x3e\n\t"                   // branch taken
        "ja %l[end]\n\t"                   // CF==0 && ZF==0
        "je %l[fail_valid]\n\t"            // ZF==1
        :
        : "m" (pa)
        : "cc", "memory"
        : fail_invalid, fail_valid, end);  // Add fail_invalid to GotoLabels to
                                           // supress the unused labels warning
fail_invalid:
    printk(KERN_ERR "%s: VMCLEAR VMfailInvalid\n", DEVICE_NAME);
    return -EINVAL;

fail_valid:
    get_vm_instruction_error(&error);
    if (error == VMXERR_VMCLEAR_INVALID_ADDRESS)
        printk(KERN_ERR
                "%s: VMCLEAR with invalid physical address\n", DEVICE_NAME);
    else  // error ==  VMCLEAR_INVALID_ADDRESS
        printk(KERN_ERR "%s: VMCLEAR with VMXON pointer\n", DEVICE_NAME);
    return -EINVAL;

end:
    return 0;
}

static inline int __init vmptrld(u64 pa)
{
    unsigned long error;

    asm volatile goto (
        "vmptrld %0\n\t"
        ".byte 0x3e\n\t"                   // branch taken
        "ja %l[end]\n\t"                   // CF==0 && ZF==0
        "je %l[fail_valid]\n\t"            // ZF==1
        :
        : "m" (pa)
        : "cc", "memory"
        : fail_invalid, fail_valid, end);  // Add fail_invalid to GotoLabels to
                                           // supress the unused labels warning

fail_invalid:
    printk(KERN_ERR "%s: VMPTRLD VMfailInvalid\n", DEVICE_NAME);
    return -EINVAL;

fail_valid:
    get_vm_instruction_error(&error);
    if (error == VMXERR_VMPTRLD_INVALID_ADDRESS)
        printk(KERN_ERR
           "%s: VMPTRLD with invalid physical address\n", DEVICE_NAME);
    else if (error == VMXERR_VMPTRLD_VMXON_POINTER)
        printk(KERN_ERR
           "%s: VMPTRLD with VMXON pointer\n", DEVICE_NAME);
    else  // error == VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID)
        printk(KERN_ERR "%s: VMPTRLD with \
            incorrect VMCS revision identifier\n", DEVICE_NAME);
    return -EINVAL;

end:
    return 0;
}

static void __init dump_field_offset(unsigned long field, size_t size)
{
#ifdef FIRST_METHOD

    int i = VMCS_DATA_OFFSET, r;
    unsigned long val;
    unsigned long *rptr_vmcs_region = (unsigned long*)((u8*)vmcs_region+i);
    bool exact_match = false;

    if (size == 16)
        val = CONST_16;
    else if (size == 32)
        val = CONST_32;
    else  // size == 64
        val = CONST_64;

    r = vmwrite(field, &val);

    if (r == 0) {
        /*
         * force-flush by VMCLEAR
         * copy VMCS data to VMCS region in memory
         */
        vmclear(__pa(vmcs_region));
        vmptrld(__pa(vmcs_region));

        while (i < PAGE_SIZE) {
            if (size == 16) {
                if ((exact_match = *((u16 *)rptr_vmcs_region) == val)) {
                    r = snprintf(wptr_msg_buf_init, BUF_LEN,
                            "%#010lx: %05d\n", field, i);
                    break;
                }
            } else if (size == 32) {
                if ((exact_match = *((u32 *)rptr_vmcs_region) == val)) {
                    r = snprintf(wptr_msg_buf_init, BUF_LEN,
                            "%#010lx: %05d\n", field, i);
                    break;
                }
            } else {  // size == 64
                if ((exact_match = *((u64 *)rptr_vmcs_region) == val)) {
                    r = snprintf(wptr_msg_buf_init, BUF_LEN,
                            "%#010lx: %05d\n", field, i);
                    break;
                }
            }

            rptr_vmcs_region = (unsigned long*)((u8*)rptr_vmcs_region+1);
            i++;
        }

        val = 0;
        vmwrite(field, &val);  // will be force-flushed the next time
                               // this function is called
    } else if (r == -EINVAL) {
        // VMWRITE VMfailInvalid
        r = snprintf(wptr_msg_buf_init, BUF_LEN, "%#010lx: failed\n", field);
    } else {  // r == -ENOTSUPP
        // VMWRITE to unsupported/read-only VMCS component
        r = snprintf(wptr_msg_buf_init, BUF_LEN, "%#010lx: fault\n", field);
    }

    if (exact_match) {
        printk(KERN_INFO "%s: exact match %lx %p %d\n",
                DEVICE_NAME, field, rptr_vmcs_region, i);
    } 

    wptr_msg_buf_init += r;

#elif SECOND_METHOD

    int r;
    unsigned long val;

    r = vmread(field, &val);
    val = val>>(size-16);
    if (r == 0) {
        r = snprintf(wptr_msg_buf_init, BUF_LEN,
            "%#010lx: %05d\n", field, (u16)val);
    } else if (r == -EINVAL) {
        // VMWRITE VMfailInvalid
        r = snprintf(wptr_msg_buf_init, BUF_LEN, "%#010lx: failed\n", field);
    } else {  // r == -ENOTSUPP
        // VMWRITE to unsupported/read-only VMCS component
        r = snprintf(wptr_msg_buf_init, BUF_LEn, "%#010lx: fault\n", field);
    }

    wptr_msg_buf_init += r;

#endif
}

static void __init dump_each_field_offset(void)
{
    int i;

    for (i = 0; i < FIELDS_16_NUM; i++)
        dump_field_offset(fields_16[i], 16);
    for (i = 0; i < FIELDS_64_NUM; i++)
        dump_field_offset(fields_64[i], 64);
    for (i = 0; i < FIELDS_32_NUM; i++)
        dump_field_offset(fields_32[i], 32);
    for (i = 0; i < FIELDS_NATURAL_NUM; i++)
        dump_field_offset(fields_natural[i], sizeof(unsigned long));
}

// Fill the VMCS region with a 16 bit-long incremental counter
static void __init fill_vmcs(void)
{
#ifndef FIRST_METHOD
    u16 val = VMCS_DATA_OFFSET;
    u16 *base = (u16 *)((u8 *)vmcs_region+VMCS_DATA_OFFSET);

    while (val < PAGE_SIZE) {
        *base = val;
        base++;
        val += 2;
    }
#endif
}

static int __init init_vmcs(void)
{
    int r;
    u32 rev_id = __rdmsr(MSR_IA32_VMX_BASIC);

    vmcs_region = (unsigned long *)kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (vmcs_region == NULL) {
        printk(KERN_ERR "%s: kzalloc\n", DEVICE_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "%s: VMCS physical address %#014lx\n",
            DEVICE_NAME, __pa(vmcs_region));
    printk(KERN_INFO "%s: Revision ID %#010x\n", DEVICE_NAME, rev_id);

    wptr_msg_buf_init = msg_buf;
    r = snprintf(wptr_msg_buf_init, BUF_LEN,
        "vmcs_revision_id: %010u\n", rev_id);
    wptr_msg_buf_init += r;

    *(u32 *)vmcs_region = rev_id;

    fill_vmcs();

    return 0;
}

static inline int __init vmxon(u64 pa)
{
    asm volatile goto (
        "vmxon %0\n\t"
        ".byte 0x3e\n\t"                   // branch taken
        "ja %l[end]\n\t"                   // CF==0 && ZF==0
        "je %l[fail_valid]\n\t"            // ZF==1
        :
        : "m" (pa)
        : "cc", "memory"
        : fail_invalid, fail_valid, end);  // Add fail_invalid to GotoLabels to
                                           // supress the unused labels warning

fail_invalid:
    printk(KERN_ERR "%s: VMXON VMfailInvalid\n", DEVICE_NAME);
    return -EINVAL;

fail_valid:
    printk(KERN_ERR "%s: VMXON executed in VMX root operation\n", DEVICE_NAME);
    return -EPERM;

end:
    return 0;
}

static int __init init_vmxon(void)
{
    // If VMX is supported, MSR is also supported in Intel's current CPU
    // lineup. Then, we don't need to check it with the CPUID instruction.
    u64 feat_ctl = __rdmsr(MSR_IA32_FEAT_CTL);
    unsigned long cr0, cr4;

    if (feat_ctl & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX) {
        if (!(feat_ctl & FEAT_CTL_LOCKED))
            wrmsrl(MSR_IA32_FEAT_CTL, feat_ctl|FEAT_CTL_LOCKED);
    } else {
        if (!(feat_ctl & FEAT_CTL_LOCKED)) {
            wrmsrl(MSR_IA32_FEAT_CTL,
                feat_ctl|FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX);
            wrmsrl(MSR_IA32_FEAT_CTL, 
                __rdmsr(MSR_IA32_FEAT_CTL)|FEAT_CTL_LOCKED);
        } else {
            printk(KERN_ERR "%s: MSR_IA32_FEAT_CTL is locked.\n", DEVICE_NAME);
            return -EPERM;
        }
    }

    // Enable MSR_IA32_VMX_CR(0|4)_FIXED1
    // and disable MSR_IA32_VMX_CR(0|4)_FIXED0.
    cr0 = read_cr0();
    cr0 &= __rdmsr(MSR_IA32_VMX_CR0_FIXED1);
    cr0 |= __rdmsr(MSR_IA32_VMX_CR0_FIXED0);
    write_cr0(cr0);

    cr4 = __read_cr4();
    cr4 &= __rdmsr(MSR_IA32_VMX_CR4_FIXED1);
    cr4 |= __rdmsr(MSR_IA32_VMX_CR4_FIXED0);
    __write_cr4(cr4);

    // Kernel allocations always succeed, unless there's
    // an insufficient amount of memory available.
    vmxon_region = (unsigned long *)kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (vmxon_region == NULL) {
        printk(KERN_ERR "%s: kzalloc\n", DEVICE_NAME);
        return -ENOMEM;
    }
    *(u32 *)vmxon_region = __rdmsr(MSR_IA32_VMX_BASIC);

    return 0;
}

static void __init cr4_clear_vmxe(void)
{
    unsigned long cr4 = __read_cr4();
    if (!(cr4 & X86_CR4_VMXE))
        return;
    cr4 |= X86_CR4_VMXE;
    __write_cr4(cr4);
}

static void __init cr4_set_vmxe(void)
{
    unsigned long cr4 = __read_cr4();
    if (cr4 & X86_CR4_VMXE)
        return;
    cr4 |= X86_CR4_VMXE;
    __write_cr4(cr4);
}

static int __init is_vmx_supported(void)
{
    struct cpuid_regs regs;
    cpuid(1, &regs.eax, &regs.ebx, &regs.ecx, &regs.edx);
    return (regs.ecx & CPUID1_ECX_VMX_MASK)? 1 : 0;
}

static int __init my_init(void)
{
    int r = 0;
    struct device *d;

    printk(KERN_INFO
        "%s: Inserting vmcs_reverse into the kernel ...", DEVICE_NAME);

    if (is_vmx_supported()) {
        cr4_set_vmxe();
        if ((r = init_vmxon()) != 0)
            goto end;
        if ((r = vmxon(__pa(vmxon_region))) != 0)
            goto free;
        if ((r = init_vmcs()) != 0)
            goto vmxoff;
        if ((r = vmptrld(__pa(vmcs_region))) != 0)
            goto vmxoff;
        dump_each_field_offset();
        vmxoff();
        kfree(vmcs_region);
        kfree(vmxon_region);
    } else {
        printk(KERN_ERR
            "%s: VMX is not supported by this processor\n", DEVICE_NAME);
        r = -ENOTSUPP;
        goto end;
    }

    if ((r = alloc_chrdev_region(&my_devt, MINOR_BASE, MINOR_N, DEVICE_NAME))) {
        printk(KERN_ERR "%s: alloc_chrdev_region %d\n", DEVICE_NAME, r);
        goto vmclear;
    }

    my_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(my_class)) {
        r = (int)PTR_ERR(my_class);
        printk(KERN_ERR "%s: class_create %d\n", DEVICE_NAME, r);
        goto fail_at_class_create;
    }

    cdev_init(&my_cdev, &my_fops);
    my_cdev.owner = THIS_MODULE;

    d = device_create(my_class, NULL, my_devt, NULL, DEVICE_NAME);
    if (IS_ERR(d)) {
        r = (int)PTR_ERR(d);
        printk(KERN_ERR "%s: device_create %d\n", DEVICE_NAME, r);
        goto fail_at_device_create;
    }

    if ((r = cdev_add(&my_cdev, my_devt, MINOR_N))) {
        printk(KERN_ERR "%s: cdev_add %d\n", DEVICE_NAME, r);
        goto fail_at_cdev_add;
    }

    printk(KERN_INFO "%s: done.\n", DEVICE_NAME);

    return 0;

// cleanup
    cdev_del(&my_cdev);

fail_at_cdev_add:
    device_destroy(my_class, my_devt);

fail_at_device_create:
    class_destroy(my_class);

fail_at_class_create:
    unregister_chrdev_region(my_devt, MINOR_N);

vmclear:
    vmclear(__pa(vmcs_region));

vmxoff:
    vmxoff();

free:
    kfree(vmcs_region);
    kfree(vmxon_region);

end:
    cr4_clear_vmxe();
    return r;
}

static void __exit my_exit(void)
{
    printk(KERN_INFO
        "%s: removing vmcs_reverse from the kernel ...", DEVICE_NAME);
    // cleanup
    device_destroy(my_class, my_devt);
    cdev_del(&my_cdev);
    class_destroy(my_class);
    unregister_chrdev_region(my_devt, MINOR_N);
    printk(KERN_INFO "%s: done.\n", DEVICE_NAME);
}


module_init(my_init);
module_exit(my_exit);
