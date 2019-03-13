#ifndef NMAP_DROPPRIV_H__
#define NMAP_DROPPRIV_H__

extern const char *drop_priv_dir(void);
extern void drop_priv(void);
extern int nmap_services_init(void);
extern int nmap_protocols_init(void);
extern void mac_prefix_init(void);
extern void etchosts_init(void);
extern void init_payloads(void);
extern "C" void proc_net_dev_init(void);

#endif /* NMAP_DROPPRIV_H__ */
