#include "linux/printk.h"
#include "net/netlink.h"
#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#ifdef pr_fmt
#   undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt "\n"

#define GEN_NETLINK_FAMILY_NAME "lsm_netlink"

// Attributes (what we send/receive)
enum {
    LSM_ATTR_UNSPEC,
    LSM_ATTR_ADDRESS,  // Memory address (unsigned long)
    LSM_ATTR_RESPONSE, // User-space response (int)
    __LSM_ATTR_MAX,
};
#define LSM_ATTR_MAX (__LSM_ATTR_MAX - 1)

// Commands (message types)
enum {
    LSM_CMD_UNSPEC,
    LSM_CMD_NOTIFY,  // Kernel → User: Send memory address
    LSM_CMD_REPLY,   // User → Kernel: Receive integer response
    __LSM_CMD_MAX,
};
#define LSM_CMD_MAX (__LSM_CMD_MAX - 1)

// Attribute policy (validation)
static struct nla_policy lsm_policy[LSM_ATTR_MAX + 1] = {
    [LSM_ATTR_ADDRESS] = { .type = NLA_U32 },
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
        .name = "lsm_mc_group"
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

    int user_response = nla_get_s32(info->attrs[LSM_ATTR_RESPONSE]);
    pr_info("LSM: Received response from user-space: %d\n", user_response);

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
    ret = nla_put_u32(skb, LSM_ATTR_ADDRESS, addr);
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
    pr_info("mcheck_mmap_addr: addr = %lx\n", addr);
    lsm_send_address(addr);
    return 0;
}
static int mcheck_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    //pr_info("mcheck_file_mprotect: start = %lx, size = %lx, reqprot = %lx, prot = %lx\n", vma->vm_start, vma->vm_end - vma->vm_start, reqprot, prot);
    return 0;
}

static int mcheck_custom_mmap_hook(unsigned long addr, unsigned long len, unsigned long prot)
{
    //pr_info("mcheck_custom_mmap_hook: addr = %lx, len = %lx, prot = %lx\n", addr, len, prot);
    return 0;
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
    pr_info("MCHECK: LSM initialized\n");
    return 0;
}

DEFINE_LSM(mcheck) = {
    .name = "mcheck",
    .init = mcheck_lsm_init,
};
    