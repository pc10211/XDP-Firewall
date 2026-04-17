#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/in.h>
#include <uapi/linux/pkt_cls.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct wl_val {
    __u8  proto;
    __u16 port;
    __u8  action;
    __u32 rate_limit;
};

struct rl_entry {
    __u64 window_start;
    __u64 count;
};

struct ip_rl_cfg {
    __u32 pps;
    __u8  enabled;
    __u8  pad[3];
};

struct ct_key {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;
    __u8  proto;
    __u8  pad[3];
};

struct ct_val {
    __u64 last_seen;
    __u64 created;
    __u8  state;
    __u8  pad[7];
};

#define CT_NEW  1
#define CT_EST  2

#define CT_TO_TCP_EST  300000000000ULL
#define CT_TO_TCP_NEW   30000000000ULL
#define CT_TO_UDP      120000000000ULL
#define CT_TO_ICMP      30000000000ULL

BPF_LPM_TRIE(wl_subnet, struct lpm_key, struct wl_val, 1024);
BPF_LPM_TRIE(bl_subnet, struct lpm_key, __u8, 1024);
BPF_HASH(wl_port, __u32, struct wl_val, 512);
BPF_HASH(bl_port, __u32, __u8, 512);
BPF_HASH(wl_icmp, __u16, __u8, 64);

BPF_ARRAY(rl_global_cfg,   __u32, 1);
BPF_ARRAY(rl_global_state, __u64, 2);
BPF_HASH(rl_proto_cfg,   __u8, __u32,          8);
BPF_HASH(rl_proto_state, __u8, struct rl_entry, 8);

BPF_LPM_TRIE(rl_ip_cfg, struct lpm_key, struct ip_rl_cfg, 1024);
BPF_HASH(rl_ip_state, __u32, struct rl_entry, 65536);

BPF_HASH(rl_port_cfg,   __u32, __u32,          512);
BPF_HASH(rl_port_state, __u32, struct rl_entry, 512);

BPF_HASH(dns_rl_cfg,   __u8, __u32,          4);
BPF_HASH(dns_rl_state, __u32, struct rl_entry, 65536);

BPF_ARRAY(stats, __u64, 8);
BPF_ARRAY(stateful_enabled, __u8, 1);
BPF_ARRAY(conn_timeout_cfg, __u64, 1);
BPF_ARRAY(ipv6_policy, __u8, 1);

BPF_HASH(bl_out_port, __u32, __u8, 512);
BPF_LPM_TRIE(bl_out_subnet, struct lpm_key, __u8, 1024);

BPF_HASH(dns_wl, __u8, __u8, 4);

struct pip_key {
    __u32 src_ip;
    __u32 port_key;
};

BPF_HASH(per_ip_port_cfg, __u32, __u32, 512);
BPF_HASH(per_ip_port_state, struct pip_key, struct rl_entry, 65536);

BPF_HASH(conntrack, struct ct_key, struct ct_val, 131072);

static __always_inline void inc(int i) {
    __u64 *v = stats.lookup(&i);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline __u64 ct_timeout(__u8 proto, __u8 state) {
    if (proto == IPPROTO_TCP)
        return (state == CT_EST) ? CT_TO_TCP_EST : CT_TO_TCP_NEW;
    if (proto == IPPROTO_UDP)
        return CT_TO_UDP;
    return CT_TO_ICMP;
}

static __always_inline int check_global(void) {
    int z = 0, o = 1;
    __u32 *lim = rl_global_cfg.lookup(&z);
    if (!lim || *lim == 0) return 0;
    __u64 now = bpf_ktime_get_ns(), win = 1000000000ULL;
    __u64 *ws = rl_global_state.lookup(&z);
    __u64 *ct = rl_global_state.lookup(&o);
    if (!ws || !ct) return 0;
    if (now - *ws >= win) {
        __sync_lock_test_and_set(ws, now);
        __sync_lock_test_and_set(ct, 1);
        return 0;
    }
    return (__sync_fetch_and_add(ct, 1) >= (__u64)*lim) ? 1 : 0;
}

static __always_inline int check_proto_rl(__u8 proto) {
    __u32 *lim = rl_proto_cfg.lookup(&proto);
    if (!lim || *lim == 0) return 0;
    __u64 now = bpf_ktime_get_ns(), win = 1000000000ULL;
    struct rl_entry *e = rl_proto_state.lookup(&proto);
    if (e) {
        if (now - e->window_start >= win) {
            __sync_lock_test_and_set(&e->window_start, now);
            __sync_lock_test_and_set(&e->count, 1);
            return 0;
        }
        return (__sync_fetch_and_add(&e->count, 1) >= *lim) ? 1 : 0;
    }
    struct rl_entry ne = { .window_start = now, .count = 1 };
    rl_proto_state.update(&proto, &ne);
    return 0;
}

static __always_inline int check_ip_rl(__u32 src_be) {
    struct lpm_key key = { .prefixlen = 32, .addr = src_be };
    struct ip_rl_cfg *cfg = rl_ip_cfg.lookup(&key);
    if (!cfg || !cfg->enabled || cfg->pps == 0) return 0;
    __u64 now = bpf_ktime_get_ns(), win = 1000000000ULL;
    struct rl_entry *e = rl_ip_state.lookup(&src_be);
    if (e) {
        if (now - e->window_start >= win) {
            __sync_lock_test_and_set(&e->window_start, now);
            __sync_lock_test_and_set(&e->count, 1);
            return 0;
        }
        return (__sync_fetch_and_add(&e->count, 1) >= cfg->pps) ? 1 : 0;
    }
    struct rl_entry ne = { .window_start = now, .count = 1 };
    rl_ip_state.update(&src_be, &ne);
    return 0;
}

static __always_inline int check_port_rl(__u32 pk) {
    __u32 *lim = rl_port_cfg.lookup(&pk);
    if (!lim || *lim == 0) return 0;
    __u64 now = bpf_ktime_get_ns(), win = 1000000000ULL;
    struct rl_entry *e = rl_port_state.lookup(&pk);
    if (e) {
        if (now - e->window_start >= win) {
            __sync_lock_test_and_set(&e->window_start, now);
            __sync_lock_test_and_set(&e->count, 1);
            return 0;
        }
        return (__sync_fetch_and_add(&e->count, 1) >= *lim) ? 1 : 0;
    }
    struct rl_entry ne = { .window_start = now, .count = 1 };
    rl_port_state.update(&pk, &ne);
    return 0;
}

static __always_inline int check_subnet_rl(__u32 src_be, struct wl_val *rv) {
    if (!rv || rv->rate_limit == 0) return 0;
    __u64 now = bpf_ktime_get_ns(), win = 1000000000ULL;
    struct rl_entry *e = rl_ip_state.lookup(&src_be);
    if (e) {
        if (now - e->window_start >= win) {
            __sync_lock_test_and_set(&e->window_start, now);
            __sync_lock_test_and_set(&e->count, 1);
            return 0;
        }
        return (__sync_fetch_and_add(&e->count, 1) >= rv->rate_limit) ? 1 : 0;
    }
    struct rl_entry ne = { .window_start = now, .count = 1 };
    rl_ip_state.update(&src_be, &ne);
    return 0;
}

static __always_inline int check_dns_rl(__u32 src_be, __u8 is_response) {
    __u32 *lim = dns_rl_cfg.lookup(&is_response);
    if (!lim || *lim == 0) return 0;
    __u64 now = bpf_ktime_get_ns(), win = 1000000000ULL;
    struct rl_entry *e = dns_rl_state.lookup(&src_be);
    if (e) {
        if (now - e->window_start >= win) {
            __sync_lock_test_and_set(&e->window_start, now);
            __sync_lock_test_and_set(&e->count, 1);
            return 0;
        }
        return (__sync_fetch_and_add(&e->count, 1) >= *lim) ? 1 : 0;
    }
    struct rl_entry ne = { .window_start = now, .count = 1 };
    dns_rl_state.update(&src_be, &ne);
    return 0;
}

static __always_inline int check_per_ip_rl(__u32 src_be, __u32 pk) {
    __u32 *lim = per_ip_port_cfg.lookup(&pk);
    if (!lim || *lim == 0) return 0;
    struct pip_key key = { .src_ip = src_be, .port_key = pk };
    __u64 now = bpf_ktime_get_ns(), win = 1000000000ULL;
    struct rl_entry *e = per_ip_port_state.lookup(&key);
    if (e) {
        if (now - e->window_start >= win) {
            __sync_lock_test_and_set(&e->window_start, now);
            __sync_lock_test_and_set(&e->count, 1);
            return 0;
        }
        return (__sync_fetch_and_add(&e->count, 1) >= *lim) ? 1 : 0;
    }
    struct rl_entry ne2 = { .window_start = now, .count = 1 };
    per_ip_port_state.update(&key, &ne2);
    return 0;
}

int tc_egress(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5) return TC_ACT_OK;

    __u8 proto = ip->protocol;
    void *l4   = (void *)ip + (ip->ihl * 4);

    struct ct_key key = {};
    key.local_ip  = ip->saddr;
    key.remote_ip = ip->daddr;
    key.proto     = proto;
    __u8 new_state = CT_NEW;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        key.local_port  = tcp->source;
        key.remote_port = tcp->dest;
        if (tcp->syn && tcp->ack) new_state = CT_EST;
        else if (tcp->ack && !tcp->syn) new_state = CT_EST;
        else new_state = CT_NEW;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        key.local_port  = udp->source;
        key.remote_port = udp->dest;
        new_state = CT_NEW;
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if ((void *)(icmp + 1) > data_end) return TC_ACT_OK;
        if (icmp->type == 8) {
            key.local_port  = icmp->un.echo.id;
            key.remote_port = 0;
            new_state = CT_NEW;
        } else if (icmp->type == 0) {
            return TC_ACT_OK;
        } else {
            return TC_ACT_OK;
        }
    } else {
        key.local_port  = 0;
        key.remote_port = 0;
        new_state = CT_NEW;
    }

    __u64 now = bpf_ktime_get_ns();
    struct ct_val *existing = conntrack.lookup(&key);
    if (existing) {
        existing->last_seen = now;
        if (new_state == CT_EST && existing->state == CT_NEW)
            existing->state = CT_EST;
    } else {
        struct ct_val val = {};
        val.last_seen = now;
        val.created   = now;
        val.state     = new_state;
        conntrack.update(&key, &val);
    }

    inc(6);
    return TC_ACT_OK;
}

int xdp_firewall(struct xdp_md *ctx) {
    void *end  = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) goto drop;
    if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        int z6 = 0;
        __u8 *v6p = ipv6_policy.lookup(&z6);
        if (!v6p || *v6p == 0) { inc(7); goto drop; }
        goto pass;
    }
    if (eth->h_proto != __constant_htons(ETH_P_IP)) goto pass;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end || ip->ihl < 5) goto drop;

    __u32 src_be = ip->saddr;
    __u32 dst_be = ip->daddr;
    __u8  proto  = ip->protocol;
    __u16 dport  = 0;
    __u16 sport  = 0;
    __u16 dport_be = 0;
    __u16 sport_be = 0;
    __u16 icmp_id_be = 0;
    __u8  icmp_type = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    __u8 b0 = (src_be >> 0) & 0xFF;
    if (b0 == 127) goto pass;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > end) goto drop;
        dport    = __be16_to_cpu(tcp->dest);
        sport    = __be16_to_cpu(tcp->source);
        dport_be = tcp->dest;
        sport_be = tcp->source;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > end) goto drop;
        dport    = __be16_to_cpu(udp->dest);
        sport    = __be16_to_cpu(udp->source);
        dport_be = udp->dest;
        sport_be = udp->source;
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if ((void *)(icmp + 1) > end) goto drop;
        icmp_type  = icmp->type;
        dport      = ((__u16)icmp->type << 8) | icmp->code;
        icmp_id_be = icmp->un.echo.id;
    }

    {
        struct lpm_key bk = { .prefixlen = 32, .addr = src_be };
        if (bl_subnet.lookup(&bk)) { inc(3); goto drop; }
    }

    if (dport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk_proto = ((__u32)proto << 16) | dport;
        __u32 pk_any   = (__u32)dport;
        if (bl_port.lookup(&pk_proto) || bl_port.lookup(&pk_any)) { inc(3); goto drop; }
    }

    if (dport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk = ((__u32)proto << 16) | dport;
        __u32 *lim = rl_port_cfg.lookup(&pk);
        if (lim && *lim > 0) {
            if (check_port_rl(pk)) { inc(2); goto drop; }
        }
        if (!lim) {
            __u32 pw = (__u32)dport;
            __u32 *lim2 = rl_port_cfg.lookup(&pw);
            if (lim2 && *lim2 > 0) {
                if (check_port_rl(pw)) { inc(2); goto drop; }
            }
        }
        if (check_per_ip_rl(src_be, pk)) { inc(2); goto drop; }
    }

    if (proto == IPPROTO_ICMP) {
        __u8 icmp_proto = IPPROTO_ICMP;
        if (check_proto_rl(icmp_proto)) { inc(2); inc(4); goto drop; }
        __u32 icmp_pk = ((__u32)IPPROTO_ICMP << 16) | 0xFFFF;
        if (check_per_ip_rl(src_be, icmp_pk)) { inc(2); inc(4); goto drop; }
    }

    {
        struct ct_key rkey = {};
        rkey.local_ip    = dst_be;
        rkey.remote_ip   = src_be;
        rkey.proto       = proto;
        int do_ct = 0;

        if (proto == IPPROTO_TCP) {
            rkey.local_port  = dport_be;
            rkey.remote_port = sport_be;
            do_ct = 1;
        } else if (proto == IPPROTO_UDP) {
            rkey.local_port  = dport_be;
            rkey.remote_port = sport_be;
            do_ct = 1;
        } else if (proto == IPPROTO_ICMP && icmp_type == 0) {
            rkey.local_port  = icmp_id_be;
            rkey.remote_port = 0;
            do_ct = 1;
        } else if (proto != IPPROTO_ICMP) {
            rkey.local_port  = dport_be;
            rkey.remote_port = sport_be;
            do_ct = 1;
        }

        if (do_ct) {
            struct ct_val *ct = conntrack.lookup(&rkey);
            if (ct) {
                __u64 now = bpf_ktime_get_ns();
                __u64 to  = ct_timeout(proto, ct->state);
                if (now - ct->last_seen < to) {
                    ct->last_seen = now;
                    if (ct->state == CT_NEW)
                        ct->state = CT_EST;
                    inc(5);
                    goto pass;
                }
                conntrack.delete(&rkey);
            }
        }
    }

    {
        struct lpm_key wk = { .prefixlen = 32, .addr = src_be };
        struct wl_val *rv = wl_subnet.lookup(&wk);
        if (rv && rv->action == 1) {
            if (rv->proto == 0 && rv->port == 0) {
                if (check_subnet_rl(src_be, rv)) { inc(2); goto drop; }
                goto pass;
            }
            if ((rv->proto == 0 || rv->proto == proto) &&
                (rv->port  == 0 || rv->port  == dport)) {
                if (check_subnet_rl(src_be, rv)) { inc(2); goto drop; }
                goto pass;
            }
        }
    }

    if (proto == IPPROTO_UDP && (dport == 53 || sport == 53)) {
        __u8 is_resp = (sport == 53) ? 1 : 0;
        __u8 dns_key = is_resp ? 1 : 0;
        __u8 *dns_allowed = dns_wl.lookup(&dns_key);
        if (dns_allowed && *dns_allowed == 1) {
            if (check_dns_rl(src_be, is_resp)) { inc(2); goto drop; }
            goto pass;
        }
        __u8 dns_any_key = 2;
        __u8 *dns_any = dns_wl.lookup(&dns_any_key);
        if (dns_any && *dns_any == 1) {
            if (check_dns_rl(src_be, is_resp)) { inc(2); goto drop; }
            goto pass;
        }
    }

    if (check_global())         { inc(2); goto drop; }
    if (proto != IPPROTO_ICMP && check_proto_rl(proto)) { inc(2); goto drop; }
    if (check_ip_rl(src_be))    { inc(2); goto drop; }

    if (proto == IPPROTO_ICMP) {
        __u16 tc     = dport;
        __u16 tc_any = (dport & 0xFF00) | 0xFF;
        __u16 all    = 0xFFFF;
        if (wl_icmp.lookup(&tc) || wl_icmp.lookup(&tc_any) || wl_icmp.lookup(&all))
            goto pass;
        inc(4); goto drop;
    }

    if (dport != 0) {
        __u32 pk = ((__u32)proto << 16) | dport;
        struct wl_val *p = wl_port.lookup(&pk);
        if (p && p->action == 1) {
            if (p->rate_limit > 0 && check_port_rl(pk)) { inc(2); goto drop; }
            goto pass;
        }
        __u32 pw = dport;
        struct wl_val *p2 = wl_port.lookup(&pw);
        if (p2 && p2->action == 1) {
            if (p2->rate_limit > 0 && check_port_rl(pw)) { inc(2); goto drop; }
            goto pass;
        }
    }

    if (sport != 0) {
        __u32 pk = ((__u32)proto << 16) | sport;
        struct wl_val *p = wl_port.lookup(&pk);
        if (p && p->action == 1) {
            if (p->rate_limit > 0 && check_port_rl(pk)) { inc(2); goto drop; }
            goto pass;
        }
        __u32 pw = sport;
        struct wl_val *p2 = wl_port.lookup(&pw);
        if (p2 && p2->action == 1) {
            if (p2->rate_limit > 0 && check_port_rl(pw)) { inc(2); goto drop; }
            goto pass;
        }
    }

drop:
    inc(1);
    return XDP_DROP;

pass:
    inc(0);
    return XDP_PASS;
}
