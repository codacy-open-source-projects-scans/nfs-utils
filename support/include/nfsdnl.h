/*
 * Helper for sending nfsd generic netlink commands.
 *
 * Used by both nfsdctl and exportfs.
 */

#ifndef NFS_UTILS_NFSDNL_H
#define NFS_UTILS_NFSDNL_H

#ifdef HAVE_NFSD_NETLINK

/**
 * nfsd_nl_cmd_str - send an nfsd netlink command carrying a string attribute
 * @cmd:   NFSD_CMD_* command number
 * @attr:  NFSD_A_* attribute number
 * @value: NUL-terminated string value for the attribute
 *
 * Opens a genetlink connection, resolves the "nfsd" family, sends a
 * single "do" command with one string attribute, waits for the ACK,
 * and cleans up.
 *
 * Returns 0 on success or a negative errno on failure.
 */
int nfsd_nl_cmd_str(int cmd, int attr, const char *value);

#else

static inline int nfsd_nl_cmd_str(int cmd, int attr, const char *value)
{
	return -ENOSYS;
}

#endif /* HAVE_NFSD_NETLINK */
#endif /* NFS_UTILS_NFSDNL_H */
