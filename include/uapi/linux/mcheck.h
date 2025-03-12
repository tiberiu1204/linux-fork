#define GEN_NETLINK_FAMILY_NAME "lsm_netlink"
#define GEN_NETLINK_GROUP_NAME "lsm_mc_group"

// Attributes (what we send/receive)
enum {
    LSM_ATTR_UNSPEC,
    LSM_ATTR_ADDRESS,  // Memory address (unsigned long)
    LSM_ATTR_RESPONSE, // User-space response (unsigned long)
    __LSM_ATTR_MAX,
};
#define LSM_ATTR_MAX (__LSM_ATTR_MAX - 1)

// Commands (message types)
enum {
    LSM_CMD_UNSPEC,
    LSM_CMD_NOTIFY,  // Kernel → User: Send memory address
    LSM_CMD_REPLY,   // User → Kernel: Receive analyzer response
    __LSM_CMD_MAX,
};
#define LSM_CMD_MAX (__LSM_CMD_MAX - 1)