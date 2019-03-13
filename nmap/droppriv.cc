#include "nmap.h"
#include "nmap_error.h"
#include "service_scan.h"
#include "utils.h"
#include "droppriv.h"

#ifndef NMAP_USER

void drop_priv(void) {}

#else

#include <sys/types.h>
#include <pwd.h>

#if HAVE_GRP_H
# include <grp.h>
#endif
#if HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif
#if HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif

#include "NmapOps.h"
extern NmapOps o;		/* option structure */

#ifndef NMAP_CHROOT_EMPTY
# ifdef NMAP_CHROOT_RESOLV
#  define NMAP_CHROOT_EMPTY NMAP_CHROOT_RESOLV
# else
#  define NMAP_CHROOT_EMPTY NULL
# endif
#endif

#ifndef NMAP_CHROOT_RESOLV
# define NMAP_CHROOT_RESOLV NULL
#endif

const char *
drop_priv_dir(void)
{
	return o.noresolve ? NMAP_CHROOT_EMPTY : NMAP_CHROOT_RESOLV;
}

void
drop_priv(void)
{
	const char *user = NMAP_USER;
	const char *dir;
	struct passwd *pw;
	cap_t   caps;

	if (geteuid())
		return;

	proc_net_dev_init();
	nmap_services_init();
	nmap_protocols_init();
	AllProbes::service_scan_init();
	mac_prefix_init();
	init_payloads();
	if (!o.noresolve) etchosts_init();

	if (setgroups(0, 0) < 0)
		fatal("setgroups failed");

	if (prctl(PR_SET_KEEPCAPS, 1))
		fatal("prctl PR_SET_KEEPCAPS failed");

	if (!(pw = getpwnam(user)))
		fatal("lookup of user \"%s\" failed", user);
	endpwent();

	if (!pw->pw_uid)
		fatal("user \"%s\" shouldn't be root", user);

	dir = drop_priv_dir();
	if (dir && (chdir(dir) || chroot(".")))
		fatal("chroot to \"%s\" failed", dir);

	if (setgid(pw->pw_gid) < 0)
		fatal("setgid failed");

	if (setreuid(pw->pw_uid, pw->pw_uid) < 0)
		fatal("setreuid failed");

	caps = cap_from_text("cap_net_raw=ep");
	if (!caps)
		fatal("cap_from_text failed");

	if (cap_set_proc(caps) < 0)
		fatal("cap_set_proc failed");

	cap_free(caps);
}

#endif /* NMAP_USER */
