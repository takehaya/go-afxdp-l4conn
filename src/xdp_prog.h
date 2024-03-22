#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

// vlan header
struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

volatile const __u16 TARGET_PORT; // replace by Go program

#define MAX_SOCKS 64

#endif  // XDP_PROG_H