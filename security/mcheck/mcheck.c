#include "linux/completion.h"
#include "linux/kthread.h"
#include "linux/mm.h"
#include "linux/mm_types.h"
#include "linux/mman.h"
#include "linux/printk.h"
#include "linux/sched.h"
#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/mcheck.h>

#ifdef pr_fmt
#   undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt "\n"

static struct task_struct *analyzer_task = NULL;
static unsigned int analyzer_response = 0;
static struct completion analyzer_ready;


// Attribute policy (validation)
static struct nla_policy lsm_policy[LSM_ATTR_MAX + 1] = {
    [LSM_ATTR_ADDRESS] = { .type = NLA_U64 },
    [LSM_ATTR_RESPONSE] = { .type = NLA_U32 },
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

    int user_response = nla_get_u32(info->attrs[LSM_ATTR_RESPONSE]);
    pr_info("LSM: Received response from user-space: %d\n", user_response);

    // register the analyzer task
    if (!analyzer_task) {
        pr_info("LSM: Received analyzer PID: %d\n", user_response);
        analyzer_task = find_task_by_vpid(user_response);
        if (!analyzer_task) {
            pr_err("LSM: Failed to find analyzer task\n");
            return -EINVAL;
        }
        return 0;
    }

    // set response and signal ready for lsm hook to continue
    analyzer_response = user_response;
    complete(&analyzer_ready);

    return 0;
}

static int lsm_send_address(unsigned long addr) {
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

    // Add the address attribute to the message
    ret = nla_put_u64_64bit(skb, LSM_ATTR_ADDRESS, addr, 0);
    if (ret) {
        pr_err("LSM: Failed to add address attribute to Netlink message\n");
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

struct completion mmap_analyzer_thread_ready;
struct mmap_analyzer_thread_data {
    struct mm_struct *analyzer_mm;
    unsigned long len;
    struct vm_area_struct *vma;

    unsigned long address;
};
static int mmap_analyzer_thread(void *arg) {
    complete(&mmap_analyzer_thread_ready);

    int ret = 0;
    struct mmap_analyzer_thread_data *data = (struct mmap_analyzer_thread_data *)arg;


    // kthread_use_mm can only be called from a kernel thread
    kthread_use_mm(data->analyzer_mm);
    data->address = vm_mmap(data->vma->vm_file, 0, data->len, PROT_READ, MAP_PRIVATE, 0);
    if (!data->analyzer_mm) {
        pr_err("mcheck_custom_mmap_hook: failed to map file\n");
        ret = -ENOMEM;
    }
    pr_info("mapped address: %lx\n", data->address);
    kthread_unuse_mm(data->analyzer_mm);
    mmput(data->analyzer_mm);


    while(!kthread_should_stop()) {
        schedule();
    }
    return ret;
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
    if (!(vma->vm_file)) {
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
    analyzer_data->len = len;
    analyzer_data->vma = vma;

    init_completion(&mmap_analyzer_thread_ready);
    struct task_struct *task = kthread_run(mmap_analyzer_thread, analyzer_data, "mmap_analyzer_thread");

    if (IS_ERR(task)) {
        pr_err("Failed to create kernel thread: %ld\n", PTR_ERR(task));
        kfree(analyzer_data);
        return 0;
    }

    wait_for_completion(&mmap_analyzer_thread_ready);

    int ret = kthread_stop(task);

    if (ret) {
        pr_err("Failed to stop kernel thread: %d\n", ret);
    } else {
        lsm_send_address(analyzer_data->address);
        wait_for_completion(&analyzer_ready);
        reinit_completion(&analyzer_ready);
    }

    kfree(analyzer_data);
    return -analyzer_response;
}

static int mcheck_custom_mprotect_hook(unsigned long addr, unsigned long len, unsigned long prot)
{
    //pr_info("mcheck_custom_mprotect_hook: addr = %lx, len = %lx, prot = %lx\n", addr, len, prot);
    return 0;
}
static struct security_hook_list mcheck_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(mmap_addr, mcheck_mmap_addr),
    LSM_HOOK_INIT(file_mprotect, mcheck_file_mprotect),
    LSM_HOOK_INIT(mmap_addr_size_prot, mcheck_custom_mmap_hook),
    LSM_HOOK_INIT(mprotect_addr_size_prot, mcheck_custom_mprotect_hook),
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
    