#include "linux/completion.h"
#include "linux/kthread.h"
#include "linux/mm.h"
#include "linux/mm_types.h"
#include "linux/mman.h"
#include "linux/mmap_lock.h"
#include "linux/printk.h"
#include "linux/sched.h"
#include "linux/sched/mm.h"
#include "linux/spinlock.h"
#include "linux/timekeeping.h"
#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/mcheck.h>
#include <linux/device.h>
#include <linux/cdev.h>

#ifdef pr_fmt
#   undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt "\n"

int init_char_device(void);

static struct task_struct *analyzer_task = NULL;
static unsigned int analyzer_response = 0;
static struct completion analyzer_ready;


// Attribute policy (validation)
static struct nla_policy lsm_policy[LSM_ATTR_MAX + 1] = {
    [LSM_ATTR_ADDRESS] = { .type = NLA_U64 },
    [LSM_ATTR_LENGTH] = { .type = NLA_U64 },
    [LSM_ATTR_RESPONSE] = { .type = NLA_S32 },
};
static int lsm_receive_reply(struct sk_buff *skb, struct genl_info *info);
// Command handler mapping
static const struct genl_ops lsm_ops[] = {
    {
        .cmd = LSM_CMD_REPLY,
        .policy = lsm_policy,
        .doit = lsm_receive_reply, // Handle user responses
    },
};

static const struct genl_multicast_group genl_lsm_mcgrps[] = {
    {
        .name = GEN_NETLINK_GROUP_NAME,
    },
};

// Define the Netlink Generic family
static struct genl_family lsm_family = {
    .name = GEN_NETLINK_FAMILY_NAME,
    .version = 1,
    .maxattr = LSM_ATTR_MAX,
    .ops = lsm_ops,
    .n_ops = ARRAY_SIZE(lsm_ops),
    .mcgrps = genl_lsm_mcgrps,
    .n_mcgrps = ARRAY_SIZE(genl_lsm_mcgrps),
};

// Function to handle user-space replies
static int lsm_receive_reply(struct sk_buff *skb, struct genl_info *info)
{
    if (!info->attrs[LSM_ATTR_RESPONSE]) {
        pr_err("LSM: No response received!\n");
        return -EINVAL;
    }

    int user_response = (int) nla_get_s32(info->attrs[LSM_ATTR_RESPONSE]);
    pr_info("LSM: Received response from user-space: %d\n", user_response);

    // register the analyzer task
    if (!analyzer_task) {
        pr_info("LSM: Received analyzer PID: %d\n", user_response);
        analyzer_task = find_task_by_vpid(user_response);
        if (!analyzer_task) {
            pr_err("LSM: Failed to find analyzer task\n");
            return -EINVAL;
        }
        init_char_device();
        return 0;
    }

    // set response and signal ready for lsm hook to continue
    analyzer_response = user_response;
    complete(&analyzer_ready);

	return 0;
}

struct mapping_info {
	unsigned long pid;
	unsigned long long init_addr;
	unsigned long mapped_addr;
	unsigned long len;
	unsigned long prot;
	unsigned long is_file_backed;
};

static int lsm_send_to_userspace(struct mapping_info *map_info)
{
    struct sk_buff *skb;
    void *msg_head;
    int ret;

    // Allocate a new Netlink message
    skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!skb) {
        pr_err("LSM: Failed to allocate new Netlink message\n");
        return -ENOMEM;
    }

    // Create the message header
    msg_head = genlmsg_put(skb, 0, 0, &lsm_family, 0, LSM_CMD_NOTIFY);
    if (!msg_head) {
        pr_err("LSM: Failed to create Netlink message header\n");
        nlmsg_free(skb);
        return -ENOMEM;
    }
    // Add the pid attribute to the message
    ret = nla_put_u64_64bit(skb, LSM_ATTR_PID, map_info->pid, 0);
    if (ret) {
        pr_err("LSM: Failed to add pid attribute to Netlink message\n");
        genlmsg_cancel(skb, msg_head);
        nlmsg_free(skb);
        return ret;
    }
    ret = nla_put_u64_64bit(skb, LSM_ATTR_INIT_ADDRESS, map_info->init_addr, 0);
    if (ret) {
        pr_err("LSM: Failed to add initial address attribute to Netlink message\n");
        genlmsg_cancel(skb, msg_head);
        nlmsg_free(skb);
        return ret;
    }
    ret = nla_put_u64_64bit(skb, LSM_ATTR_ADDRESS, map_info->mapped_addr, 0);
    if (ret) {
        pr_err("LSM: Failed to add mapped address attribute to Netlink message\n");
        genlmsg_cancel(skb, msg_head);
        nlmsg_free(skb);
        return ret;
    }
    ret = nla_put_u64_64bit(skb, LSM_ATTR_LENGTH, map_info->len, 0);
    if (ret) {
        pr_err("LSM: Failed to add length attribute to Netlink message\n");
        genlmsg_cancel(skb, msg_head);
        nlmsg_free(skb);
        return ret;
    }
    ret = nla_put_u64_64bit(skb, LSM_ATTR_PROT, map_info->prot, 0);
    if (ret) {
        pr_err("LSM: Failed to add prot attribute to Netlink message\n");
        genlmsg_cancel(skb, msg_head);
        nlmsg_free(skb);
        return ret;
    }
    ret = nla_put_u64_64bit(skb, LSM_ATTR_IS_FILE_BACKED, map_info->is_file_backed, 0);
    if (ret) {
        pr_err("LSM: Failed to add is_file_backed attribute to Netlink message\n");
        genlmsg_cancel(skb, msg_head);
        nlmsg_free(skb);
        return ret;
    }

    // Finalize the message
    genlmsg_end(skb, msg_head);

    // Send the message
    ret = genlmsg_multicast(&lsm_family, skb, 0, 0, GFP_KERNEL);
    if (ret == -ESRCH) {
		pr_warn("multicast message sent, but nobody was listening...\n");
	} else if (ret) {
		pr_err("failed to send multicast genl message; ret = %d\n", ret);
	} else {
		pr_info("multicast message sent\n");
	}

    return ret;
}

static int mcheck_mmap_addr(unsigned long addr)
{
    // pr_info("mcheck_mmap_addr: addr = %lx\n", addr);
    // lsm_send_address(addr);
    return 0;
}
static int mcheck_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    //pr_info("mcheck_file_mprotect: start = %lx, size = %lx, reqprot = %lx, prot = %lx\n", vma->vm_start, vma->vm_end - vma->vm_start, reqprot, prot);
    return 0;
}

static struct completion analyzer_mmap_done;
static struct completion analyzer_munmap_ready;


struct mmap_analyzer_thread_data {
    struct mm_struct *analyzer_mm;
    unsigned long len;
    struct vm_area_struct *vma;
    void *init_data;

    unsigned long address;
};
static int mmap_analyzer_thread(void *arg) {

    struct mmap_analyzer_thread_data *data = (struct mmap_analyzer_thread_data *)arg;

    // kthread_use_mm can only be called from a kernel thread
    kthread_use_mm(data->analyzer_mm);
    if  (data->vma) {
        data->address = vm_mmap(data->vma->vm_file, 0, data->len, PROT_READ, MAP_PRIVATE, data->vma->vm_pgoff * PAGE_SIZE);
    } else {
        if (data->init_data) {
            data->address = vm_mmap(NULL, 0, data->len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
        } else {
            data->address = vm_mmap(NULL, 0, data->len, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0);
        }
        if (data->address && data->init_data) { 
            int res = copy_to_user((void __user *)data->address, data->init_data, data->len);
            if (res) {
                pr_err("mcheck_custom_mmap_hook: failed to copy data to user\n");
                vm_munmap(data->address, data->len);
                data->address = 0;
            }
        }
    }

    init_completion(&analyzer_munmap_ready);
    complete(&analyzer_mmap_done);

    if (!data->address) {
        pr_err("mcheck_custom_mmap_hook: failed to map file\n");
        while(!kthread_should_stop()) {
            schedule();
        }
        return -ENOMEM;
    }
        
    pr_info("mapped address: %lx\n", data->address);
    wait_for_completion(&analyzer_munmap_ready);

    vm_munmap(data->address, data->len);
    kthread_unuse_mm(data->analyzer_mm);

    while(!kthread_should_stop()) {
        schedule();
    }
    return 0;
}


static int mcheck_custom_mmap_hook(unsigned long addr, unsigned long len, unsigned long prot)
{
    // pr_info("mcheck_custom_mmap_hook: addr = %lx, len = %lx, prot = %lx\n", addr, len, prot);

    // analyzer task is not set yet
    if (!analyzer_task) {
        return 0;
    }

    // we are only interested in executable mappings
    if (!(prot & PROT_EXEC)) {
        return 0;
    }

    // mapping in analyzer's address space
    if (current->active_mm == analyzer_task->mm) {
        return 0;
    }

    struct vm_area_struct *vma = find_vma(current->mm, addr);
    if (!vma) {
        pr_err("mcheck_custom_mmap_hook: failed to find vma\n");
        return -EINVAL;
    }

    // we are only interested in file-backed mappings
    // in the case of jitted code, we are actually interested
    // in annonymous mappings too
    /*if (!(vma->vm_file)) {
        return 0;
    }*/

    struct mm_struct *analyzer_mm = get_task_mm(analyzer_task);
    if (!analyzer_mm) {
        pr_err("mcheck_custom_mmap_hook: failed to get analyzer mm\n");
        return -EINVAL;
    }

    struct mmap_analyzer_thread_data *analyzer_data = kmalloc(sizeof(struct mmap_analyzer_thread_data), GFP_KERNEL);
    if (!analyzer_data) {
        pr_err("mcheck_custom_mmap_hook: failed to allocate memory\n");
        return -ENOMEM;
    }
    analyzer_data->analyzer_mm = analyzer_mm;
    analyzer_data->len = len;
    analyzer_data->vma = vma;
    analyzer_data->address = 0;
    analyzer_data->init_data = NULL;

    init_completion(&analyzer_mmap_done);
    struct task_struct *task = kthread_run(mmap_analyzer_thread, analyzer_data, "mmap_analyzer_thread");

    if (IS_ERR(task)) {
        pr_err("Failed to create kernel thread: %ld\n", PTR_ERR(task));
        kfree(analyzer_data);
        return 0;
    }

    wait_for_completion(&analyzer_mmap_done);
    if (!analyzer_data->address) {
        pr_err("mcheck_custom_mmap_hook: failed to map file\n");
        kthread_stop(task);
        mmput(analyzer_mm);
        kfree(analyzer_data);
        return 0;
    }

	struct mapping_info info = {
		.pid = current->pid,
		.init_addr = addr,
		.mapped_addr = analyzer_data->address,
		.len = len,
		.prot = prot,
		.is_file_backed = vma->vm_file != NULL,
	};
    // send info to user-space
    lsm_send_to_userspace(&info);

    // wait for user-space analysis
    wait_for_completion(&analyzer_ready);
    reinit_completion(&analyzer_ready);

    // ready to unmap file
    complete(&analyzer_munmap_ready);

    kthread_stop(task);
    mmput(analyzer_mm);

    kfree(analyzer_data);
    return -analyzer_response;
}

static int mcheck_custom_mprotect_hook(unsigned long addr, unsigned long len, unsigned long prot)
{
    //pr_info("mcheck_custom_mprotect_hook: addr = %lx, len = %lx, prot = %lx\n", addr, len, prot);

    // analyzer task is not set yet
    if (!analyzer_task) {
        return 0;
    }

    // we are only interested in executable mappings
    if (!(prot & PROT_EXEC)) {
        return 0;
    }

    // mapping in analyzer's address space
    if (current->active_mm == analyzer_task->mm) {
        return 0;
    }

    // alloc memory in analyzer's address space
    struct mm_struct *analyzer_mm = get_task_mm(analyzer_task);
    if (!analyzer_mm) {
        pr_err("mcheck_custom_mmap_hook: failed to get analyzer mm\n");
        return -EINVAL;
    }

    struct mmap_analyzer_thread_data *analyzer_data = kmalloc(sizeof(struct mmap_analyzer_thread_data), GFP_KERNEL);
    if (!analyzer_data) {
        pr_err("mcheck_custom_mmap_hook: failed to allocate memory\n");
        return -ENOMEM;
    }
    analyzer_data->analyzer_mm = analyzer_mm;
    analyzer_data->len = len;
    analyzer_data->vma = NULL;
    analyzer_data->address = 0;
    analyzer_data->init_data = NULL;

    init_completion (&analyzer_mmap_done);
    struct task_struct *task = kthread_run(mmap_analyzer_thread, analyzer_data, "mmap_analyzer_thread");

    if (IS_ERR(task)) {
        pr_err("Failed to create kernel thread: %ld\n", PTR_ERR(task));
        kfree(analyzer_data);
        return 0;
    }

    // pin pages
    unsigned long pages_no = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
    struct page **pages = kmalloc(sizeof(struct page *) * pages_no, GFP_KERNEL);
    if (!pages) {
        pr_err("mcheck_custom_mprotect_hook: failed to allocate memory\n");
        return -ENOMEM;
    }

    pr_info("try to pin %lu pages\n", pages_no);

    // mmap_lock already acquired in mprotect!
    int pinned_pages = get_user_pages(addr, pages_no, FOLL_FORCE, pages);
    if (pinned_pages < 0) {
        pr_err("mcheck_custom_mprotect_hook: failed to pin pages\n");
        kfree(pages);
        return -ENOMEM;
    }

    pr_info("pinning ok : pages_no = %lu, pinned_pages = %d\n", pages_no, pinned_pages);

    // memory allocation in analyzer's address space is done
    wait_for_completion(&analyzer_mmap_done);

    if (!analyzer_data->address) {
        pr_err("mcheck_custom_mprotect_hook: failed to mmap in analyzer\n");
        // unpin pages
        for (int i = 0; i < pinned_pages; i++) {
            put_page(pages[i]);
        }
        kfree(pages);
        kthread_stop(task);
        kfree(analyzer_data);
        mmput(analyzer_mm);
        return 0;
    }

    // map pages in analyzer's address space
    int remapping_ok = 1;
    mmap_write_lock(analyzer_mm);
    struct vm_area_struct *analyzer_vma = find_vma(analyzer_mm, analyzer_data->address);

    // copy-on-write mappings are a special case, we don't need to write so we clear the flag
    vm_flags_clear(analyzer_vma, VM_MAYWRITE);
    if (!analyzer_vma) {
        pr_err("mcheck_custom_mprotect_hook: failed to find vma\n");
        remapping_ok = 0;
    }
    for (int i = 0; i < pinned_pages; i++) {
        if (!remapping_ok) {
            break;
        }
        unsigned long pfn = page_to_pfn(pages[i]);
        unsigned long size = PAGE_SIZE;
        if (i == pinned_pages - 1) {
            size = len - i * PAGE_SIZE;
        }
        int ret = remap_pfn_range(analyzer_vma, analyzer_data->address + i * PAGE_SIZE, pfn, size, analyzer_vma->vm_page_prot);
        if (ret) {
            pr_err("mcheck_custom_mprotect_hook: remap_pfn_range err = %d; i = %d\n", ret, i);
            remapping_ok = 0;
        }
    }
    mmap_write_unlock(analyzer_mm);

    if (remapping_ok) {
        pr_info("mcheck_custom_mprotect_hook: remapping ok\n");
		struct mapping_info info = {
			.pid = current->pid,
			.init_addr = addr,
			.mapped_addr = analyzer_data->address,
			.len = len,
			.prot = prot,
			.is_file_backed = analyzer_vma->vm_file != NULL,
		};
        lsm_send_to_userspace(&info);
        wait_for_completion(&analyzer_ready);
        reinit_completion(&analyzer_ready);
    } else {
        pr_err("mcheck_custom_mprotect_hook: remapping failed\n");
    }

    // unmap memory from analyzer
    complete(&analyzer_munmap_ready);
    kthread_stop(task);
    mmput(analyzer_mm);

    // unpin pages
    for (int i = 0; i < pinned_pages; i++) {
        put_page(pages[i]);
    }
    kfree(pages);
    kfree(analyzer_data);

    if (remapping_ok) {
        return -analyzer_response;
    }
    return 0;
}

#ifdef CONFIG_BPF_SYSCALL
static int bpf_prog_hook(struct bpf_prog *prog, union bpf_attr *attr, struct bpf_token *token)
{
    if (!prog->jited) {
        // only jited programs are interesting
        return 0;
    }
    if (!prog->bpf_func) {
        pr_err("bpf_prog_hook: prog bpf_func is NULL\n");
        return 0;
    }

    // analyzer task is not set yet
    if (!analyzer_task) {
        return 0;
    }

    struct mm_struct *analyzer_mm = get_task_mm(analyzer_task);
    if (!analyzer_mm) {
        pr_err("mcheck_custom_mmap_hook: failed to get analyzer mm\n");
        return -EINVAL;
    }

    struct mmap_analyzer_thread_data *analyzer_data = kmalloc(sizeof(struct mmap_analyzer_thread_data), GFP_KERNEL);
    if (!analyzer_data) {
        pr_err("mcheck_custom_mmap_hook: failed to allocate memory\n");
        return -ENOMEM;
    }
    analyzer_data->analyzer_mm = analyzer_mm;
    analyzer_data->len = prog->jited_len;
    analyzer_data->vma = NULL;
    analyzer_data->address = 0;
    analyzer_data->init_data = prog->bpf_func;

    init_completion(&analyzer_mmap_done);
    struct task_struct *task = kthread_run(mmap_analyzer_thread, analyzer_data, "mmap_analyzer_thread");
    if (IS_ERR(task)) {
        pr_err("Failed to create kernel thread: %ld\n", PTR_ERR(task));
        kfree(analyzer_data);
        return 0;
    }
    wait_for_completion(&analyzer_mmap_done);

    if (!analyzer_data->address) {
        pr_err("mcheck_custom_mmap_hook: failed to mmap in analyzer\n");
        kthread_stop(task);
        kfree(analyzer_data);
        return 0;
    }

    // send info to user-space
    lsm_send_to_userspace(analyzer_data->address, prog->jited_len);

    // wait for user-space analysis
    wait_for_completion(&analyzer_ready);
    reinit_completion(&analyzer_ready);

    // ready to unmap file
    complete(&analyzer_munmap_ready);

    kthread_stop(task);
    mmput(analyzer_mm);
    kfree(analyzer_data);

    return -analyzer_response;
}
#endif

static struct security_hook_list mcheck_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(mmap_addr, mcheck_mmap_addr),
    LSM_HOOK_INIT(file_mprotect, mcheck_file_mprotect),
    LSM_HOOK_INIT(mmap_addr_size_prot, mcheck_custom_mmap_hook),
    LSM_HOOK_INIT(mprotect_addr_size_prot, mcheck_custom_mprotect_hook),
    #ifdef CONFIG_BPF_SYSCALL
    LSM_HOOK_INIT(bpf_prog_load, bpf_prog_hook),
    #endif
};

static const struct lsm_id mcheck_lsmid = {
	.name = "mcheck",
	.id = LSM_ID_MCHECK,
};

static int __init mcheck_lsm_init(void)
{
    security_add_hooks(mcheck_hooks, ARRAY_SIZE(mcheck_hooks),
               &mcheck_lsmid);

    int ret = genl_register_family(&lsm_family);
    if (ret) {
        pr_err("LSM: Failed to register Netlink family\n");
        return ret;
    }

    init_completion(&analyzer_ready);
    pr_info("MCHECK: LSM initialized\n");
    return 0;
}

DEFINE_LSM(mcheck) = {
    .name = "mcheck",
    .init = mcheck_lsm_init,
};


#define DEVICE_NAME "lsm_perf"
#define CLASS_NAME "lsm_perf_class"
#define PERFBUF_SIZE 40960

static dev_t perf_dev;
static struct cdev perf_cdev;
static struct class *perf_class;
static char *perf_buffer;
static size_t perf_buf_head = 0;
static size_t perf_buf_tail = 0;
static DEFINE_SPINLOCK(perf_lock);

static ssize_t perfchar_read(struct file *filep, char __user *buf, size_t len, loff_t *offset) {
    ssize_t ret = 0;

    spin_lock(&perf_lock);

    if (perf_buf_head == perf_buf_tail) {
        spin_unlock(&perf_lock);
        return 0;  // No data to read
    }

    // Calculate the available data in the buffer
    size_t available_data = (perf_buf_head >= perf_buf_tail)
                                ? (perf_buf_head - perf_buf_tail)
                                : (PERFBUF_SIZE - perf_buf_tail + perf_buf_head);

    // Limit the read length to the available data
    if (len > available_data) {
        len = available_data;
    }

    if (perf_buf_tail + len <= PERFBUF_SIZE) {
        // Single contiguous read
        if (copy_to_user(buf, perf_buffer + perf_buf_tail, len) != 0) {
            spin_unlock(&perf_lock);
            return -EFAULT;
        }
        perf_buf_tail = (perf_buf_tail + len) % PERFBUF_SIZE;
    } else {
        // Split read into two parts
        size_t first_part = PERFBUF_SIZE - perf_buf_tail;
        size_t second_part = len - first_part;

        if (copy_to_user(buf, perf_buffer + perf_buf_tail, first_part) != 0 ||
            copy_to_user(buf + first_part, perf_buffer, second_part) != 0) {
            spin_unlock(&perf_lock);
            return -EFAULT;
        }

        perf_buf_tail = second_part;
    }

    ret = len;
    spin_unlock(&perf_lock);
    return ret;
}

static void perfchar_write(const char *data, size_t len) {
    spin_lock(&perf_lock);

    // Write data in two parts if it wraps around the buffer boundary
    if (perf_buf_head + len <= PERFBUF_SIZE) {
        // Single contiguous write
        memcpy(perf_buffer + perf_buf_head, data, len);
        perf_buf_head = (perf_buf_head + len) % PERFBUF_SIZE;
    } else {
        // Split write into two parts
        size_t first_part = PERFBUF_SIZE - perf_buf_head;
        size_t second_part = len - first_part;

        memcpy(perf_buffer + perf_buf_head, data, first_part);
        memcpy(perf_buffer, data + first_part, second_part);

        perf_buf_head = second_part;
    }

    // Overwrite old data if the buffer is full
    if (perf_buf_head == perf_buf_tail) {
        perf_buf_tail = (perf_buf_tail + len) % PERFBUF_SIZE;
    }

    spin_unlock(&perf_lock);
}

static const struct file_operations perf_fops = {
    .owner = THIS_MODULE,
    .read = perfchar_read,
};

int init_char_device(void) {
    int ret;

    perf_buffer = kzalloc(PERFBUF_SIZE, GFP_KERNEL);
    if (!perf_buffer)
        return -ENOMEM;

    ret = alloc_chrdev_region(&perf_dev, 0, 1, DEVICE_NAME);
    if (ret < 0)
        return ret;

    cdev_init(&perf_cdev, &perf_fops);
    perf_cdev.owner = THIS_MODULE;

    ret = cdev_add(&perf_cdev, perf_dev, 1);
    if (ret)
        goto err_unregister;

    perf_class = class_create(CLASS_NAME);
    if (IS_ERR(perf_class)) {
        ret = PTR_ERR(perf_class);
        goto err_cdev_del;
    }

    if (IS_ERR(device_create(perf_class, NULL, perf_dev, NULL, DEVICE_NAME))) {
        ret = -ENOMEM;
        goto err_class_destroy;
    }

    pr_info("Performance char device initialized\n");
    return 0;

err_class_destroy:
    class_destroy(perf_class);
err_cdev_del:
    cdev_del(&perf_cdev);
err_unregister:
    unregister_chrdev_region(perf_dev, 1);
    kfree(perf_buffer);
    return ret;
}

uint64_t mmap_hook_start_time = 0;
uint64_t mprotect_hook_start_time = 0;
uint64_t lsm_send_to_userspace_start_time = 0;
uint64_t lsm_receive_reply_start_time = 0;
uint64_t mmap_analyzer_thread_start_time = 0;

uint64_t mmap_hook_counter = 0;
uint64_t mprotect_hook_counter = 0;

char in_mmap_hook = 0;
char in_mprotect_hook = 0;

char mmap_relevant = 0;
char mprotect_relevant = 0;

__attribute__((no_instrument_function))
void __cyg_profile_func_enter(void *this_fn, void *call_site)
{
    if (analyzer_task == NULL) {
        return;
    }
    if (this_fn == mcheck_custom_mmap_hook) {
        mmap_hook_start_time = ktime_get_ns();
        in_mmap_hook++;
        mmap_relevant = 0;
    } else if (this_fn == mcheck_custom_mprotect_hook) {
        mprotect_hook_start_time = ktime_get_ns();
        in_mprotect_hook = 1;
        mprotect_relevant = 0;
    } else if (this_fn == lsm_send_to_userspace) {
        lsm_send_to_userspace_start_time = ktime_get_ns();
    } else if (this_fn == lsm_receive_reply) {
        lsm_receive_reply_start_time = ktime_get_ns();
    } else if (this_fn == mmap_analyzer_thread) {
        mmap_analyzer_thread_start_time = ktime_get_ns();
    }
}

__attribute__((no_instrument_function))
void __cyg_profile_func_exit(void *this_fn, void *call_site)
{
    if (analyzer_task == NULL) {
        return;
    }
    if (this_fn == mcheck_custom_mmap_hook) {
        uint64_t mmap_hook_end_time = ktime_get_ns();
        in_mmap_hook--;
        if (!mmap_relevant) {
            return;            
        }
        // pr_info("mcheck_custom_mmap_hook: elapsed time = %llu ns\n", mmap_hook_end_time - mmap_hook_start_time);

        char temp_buffer[64];
        int len = snprintf(temp_buffer, sizeof(temp_buffer), "mmap,mmap_hook,%llu,%llu\n", mmap_hook_counter, mmap_hook_end_time - mmap_hook_start_time);

        perfchar_write(temp_buffer, len);
        pr_info("exiting in_mmap_hook = %d\n", in_mmap_hook);
        mmap_hook_counter++;
    } else if (this_fn == mcheck_custom_mprotect_hook) {
        uint64_t mprotect_hook_end_time = ktime_get_ns();
        in_mprotect_hook = 0;
        if (!mprotect_relevant) {
            return;            
        }
        // pr_info("mcheck_custom_mprotect_hook: elapsed time = %llu ns\n", mprotect_hook_end_time - mprotect_hook_start_time);

        char temp_buffer[64];
        int len = snprintf(temp_buffer, sizeof(temp_buffer), "mprotect,mprotect_hook,%llu,%llu\n", mprotect_hook_counter, mprotect_hook_end_time - mprotect_hook_start_time);

        perfchar_write(temp_buffer, len);
        mprotect_hook_counter++;
    } else if (this_fn == lsm_send_to_userspace) {
        uint64_t lsm_send_to_userspace_end_time = ktime_get_ns();
        pr_info("lsm_send_to_userspace: elapsed time = %llu ns\n", lsm_send_to_userspace_end_time - lsm_send_to_userspace_start_time);
        pr_info("in_mmap_hook = %d, in_mprotect_hook = %d\n", in_mmap_hook, in_mprotect_hook);
        
        char temp_buffer[64];
        int len = 0;

        if (in_mmap_hook) {
            mmap_relevant = 1;
            len = snprintf(temp_buffer, sizeof(temp_buffer), "mmap,lsm_send_to_userspace,%llu,%llu\n", mmap_hook_counter, lsm_send_to_userspace_end_time - lsm_send_to_userspace_start_time);
        } else if (in_mprotect_hook) {
            mprotect_relevant = 1;
            len = snprintf(temp_buffer, sizeof(temp_buffer), "mprotect,lsm_send_to_userspace,%llu,%llu\n", mprotect_hook_counter, lsm_send_to_userspace_end_time - lsm_send_to_userspace_start_time);
        }

        perfchar_write(temp_buffer, len);
    } else if (this_fn == lsm_receive_reply) {
        if (lsm_receive_reply_start_time == 0) {
            return;
        }
        uint64_t lsm_receive_reply_end_time = ktime_get_ns();
        // pr_info("lsm_receive_reply: elapsed time = %llu ns\n", lsm_receive_reply_end_time - lsm_receive_reply_start_time);

        char temp_buffer[64];
        int len = 0;

        if (in_mmap_hook) {
            len = snprintf(temp_buffer, sizeof(temp_buffer), "mmap,lsm_receive_reply,%llu,%llu\n", mmap_hook_counter, lsm_receive_reply_end_time - lsm_receive_reply_start_time);
        } else if (in_mprotect_hook) {
            len = snprintf(temp_buffer, sizeof(temp_buffer), "mprotect,lsm_receive_reply,%llu,%llu\n", mprotect_hook_counter, lsm_receive_reply_end_time - lsm_receive_reply_start_time);
        }

        perfchar_write(temp_buffer, len);
    } else if (this_fn == mmap_analyzer_thread) {
        uint64_t mmap_analyzer_thread_end_time = ktime_get_ns();
        // pr_info("mmap_analyzer_thread: elapsed time = %llu ns\n", mmap_analyzer_thread_end_time - mmap_analyzer_thread_start_time);

        char temp_buffer[64];
        int len = 0;
        
        if (in_mmap_hook) {
            len = snprintf(temp_buffer, sizeof(temp_buffer), "mmap,mmap_analyzer_thread,%llu,%llu\n", mmap_hook_counter, mmap_analyzer_thread_end_time - mmap_analyzer_thread_start_time);
        } else if (in_mprotect_hook) {
            len = snprintf(temp_buffer, sizeof(temp_buffer), "mprotect,mmap_analyzer_thread,%llu,%llu\n", mprotect_hook_counter, mmap_analyzer_thread_end_time - mmap_analyzer_thread_start_time);
        }

        perfchar_write(temp_buffer, len);
    }
}
