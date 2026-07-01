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
    __u32 rule_id;
};

struct rl_entry {
    __u64 window_start;
    __u64 count;
};

struct ip_rl_cfg {
    __u32 pps;
    __u8  enabled;
    __u8  pad[3];
    __u32 rule_id;
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

#define CT_NEW 1
#define CT_EST 2
#define CT_TO_TCP_EST 300000000000ULL
#define CT_TO_TCP_NEW 30000000000ULL
#define CT_TO_UDP 120000000000ULL
#define CT_TO_ICMP 30000000000ULL

BPF_LPM_TRIE(wl_subnet, struct lpm_key, struct wl_val, 1024);
BPF_LPM_TRIE(bl_subnet, struct lpm_key, struct wl_val, 1024);
BPF_HASH(wl_port, __u32, struct wl_val, 512);
BPF_HASH(bl_port, __u32, struct wl_val, 512);
BPF_HASH(wl_icmp, __u16, struct wl_val, 64);
BPF_ARRAY(rl_global_cfg, __u32, 1);
BPF_ARRAY(rl_global_state, __u64, 2);
BPF_ARRAY(rl_global_rule, __u32, 1);
BPF_HASH(rl_proto_cfg, __u8, __u32, 8);
BPF_HASH(rl_proto_state, __u8, struct rl_entry, 8);
BPF_HASH(rl_proto_rule, __u8, __u32, 8);
BPF_LPM_TRIE(rl_ip_cfg, struct lpm_key, struct ip_rl_cfg, 1024);
BPF_HASH(rl_ip_state, __u32, struct rl_entry, 65536);
BPF_HASH(rl_port_cfg, __u32, __u32, 512);
BPF_HASH(rl_port_state, __u32, struct rl_entry, 512);
BPF_HASH(rl_port_rule, __u32, __u32, 512);
BPF_HASH(dns_rl_cfg, __u8, __u32, 4);
BPF_HASH(dns_rl_state, __u32, struct rl_entry, 65536);
BPF_HASH(dns_rule, __u8, __u32, 4);
BPF_ARRAY(stats, __u64, 10);
BPF_ARRAY(stateful_enabled, __u8, 1);
BPF_ARRAY(conn_timeout_cfg, __u64, 1);
BPF_ARRAY(ipv6_policy, __u8, 1);
BPF_HASH(bl_out_port, __u32, struct wl_val, 512);
BPF_LPM_TRIE(bl_out_subnet, struct lpm_key, struct wl_val, 1024);
BPF_HASH(dns_wl, __u8, __u8, 4);

struct pip_key {
    __u32 src_ip;
    __u32 port_key;
};

BPF_HASH(per_ip_port_cfg, __u32, __u32, 512);
BPF_HASH(per_ip_port_rule, __u32, __u32, 512);
BPF_HASH(per_ip_port_state, struct pip_key, struct rl_entry, 65536);
BPF_HASH(conntrack, struct ct_key, struct ct_val, 131072);
BPF_ARRAY(proto_pkts, __u64, 8);
BPF_ARRAY(proto_bytes, __u64, 8);
BPF_ARRAY(egress_pkts, __u64, 4);
BPF_ARRAY(egress_bytes, __u64, 4);
BPF_ARRAY(egress_drop_pkts, __u64, 4);
BPF_ARRAY(egress_drop_bytes, __u64, 4);
BPF_ARRAY(rule_hits, __u64, 1024);
BPF_ARRAY(rule_pass_hits, __u64, 1024);
BPF_ARRAY(rule_drop_hits, __u64, 1024);

static __always_inline void inc(int i) {
    __u64 *v = stats.lookup(&i);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline int proto_slot(__u8 proto) {
    if (proto == IPPROTO_TCP) return 0;
    if (proto == IPPROTO_UDP) return 1;
    if (proto == IPPROTO_ICMP) return 2;
    return 3;
}

static __always_inline void inc_proto(int slot, __u8 is_drop, __u32 bytes) {
    int idx = (slot << 1) | (is_drop & 1);
    if (idx < 0 || idx >= 8) return;
    __u64 *p = proto_pkts.lookup(&idx);
    if (p) __sync_fetch_and_add(p, 1);
    __u64 *b = proto_bytes.lookup(&idx);
    if (b) __sync_fetch_and_add(b, (__u64)bytes);
}

static __always_inline void inc_egress(int slot, __u32 bytes) {
    if (slot < 0 || slot >= 4) return;
    __u64 *p = egress_pkts.lookup(&slot);
    if (p) __sync_fetch_and_add(p, 1);
    __u64 *b = egress_bytes.lookup(&slot);
    if (b) __sync_fetch_and_add(b, (__u64)bytes);
}

static __always_inline void inc_egress_drop(int slot, __u32 bytes) {
    if (slot < 0 || slot >= 4) return;
    __u64 *p = egress_drop_pkts.lookup(&slot);
    if (p) __sync_fetch_and_add(p, 1);
    __u64 *b = egress_drop_bytes.lookup(&slot);
    if (b) __sync_fetch_and_add(b, (__u64)bytes);
}

static __always_inline void inc_rule(__u32 rid) {
    if (rid == 0 || rid >= 1024) return;
    int idx = (int)rid;
    __u64 *p = rule_hits.lookup(&idx);
    if (p) __sync_fetch_and_add(p, 1);
}

static __always_inline void inc_rule_pass(__u32 rid) {
    if (rid == 0 || rid >= 1024) return;
    int idx = (int)rid;
    __u64 *p = rule_pass_hits.lookup(&idx);
    if (p) __sync_fetch_and_add(p, 1);
}

static __always_inline void inc_rule_drop(__u32 rid) {
    if (rid == 0 || rid >= 1024) return;
    int idx = (int)rid;
    __u64 *p = rule_drop_hits.lookup(&idx);
    if (p) __sync_fetch_and_add(p, 1);
}

static __always_inline __u64 ct_timeout(__u8 proto, __u8 state) {
    if (proto == IPPROTO_TCP) return (state == CT_EST) ? CT_TO_TCP_EST : CT_TO_TCP_NEW;
    if (proto == IPPROTO_UDP) return CT_TO_UDP;
    return CT_TO_ICMP;
}

static __always_inline int ct_enabled(void) {
    int z = 0;
    __u8 *v = stateful_enabled.lookup(&z);
    return (v && *v) ? 1 : 0;
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

static __always_inline int check_ip_rl(__u32 src_be, __u32 *matched_rule) {
    struct lpm_key key = { .prefixlen = 32, .addr = src_be };
    struct ip_rl_cfg *cfg = rl_ip_cfg.lookup(&key);
    if (!cfg || !cfg->enabled || cfg->pps == 0) return 0;
    if (matched_rule) *matched_rule = cfg->rule_id;
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
    struct rl_entry ne = { .window_start = now, .count = 1 };
    per_ip_port_state.update(&key, &ne);
    return 0;
}

int tc_egress(struct __sk_buff *skb) {
    if (!ct_enabled()) return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5) return TC_ACT_OK;

    __u8 proto = ip->protocol;
    int pslot = proto_slot(proto);
    void *l4 = (void *)ip + (ip->ihl * 4);
    __u32 bytes = (__u32)(data_end - data);
    __u16 dport = 0;
    __u16 sport = 0;
    __u32 matched_rule = 0;

    struct ct_key key = {};
    key.local_ip = ip->saddr;
    key.remote_ip = ip->daddr;
    key.proto = proto;
    __u8 new_state = CT_NEW;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        key.local_port = tcp->source;
        key.remote_port = tcp->dest;
        sport = __be16_to_cpu(tcp->source);
        dport = __be16_to_cpu(tcp->dest);
        if (tcp->syn && tcp->ack) new_state = CT_EST;
        else if (tcp->ack && !tcp->syn) new_state = CT_EST;
        else new_state = CT_NEW;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        key.local_port = udp->source;
        key.remote_port = udp->dest;
        sport = __be16_to_cpu(udp->source);
        dport = __be16_to_cpu(udp->dest);
        new_state = CT_NEW;
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if ((void *)(icmp + 1) > data_end) return TC_ACT_OK;
        if (icmp->type == 8) {
            key.local_port = icmp->un.echo.id;
            key.remote_port = 0;
            new_state = CT_NEW;
        } else {
            return TC_ACT_OK;
        }
    } else {
        key.local_port = 0;
        key.remote_port = 0;
        new_state = CT_NEW;
    }

    {
        struct lpm_key bk = { .prefixlen = 32, .addr = key.remote_ip };
        struct wl_val *bv = bl_out_subnet.lookup(&bk);
        if (bv && bv->action == 1) {
            if (bv->proto == 0 && bv->port == 0) {
                matched_rule = bv->rule_id;
                inc(7);
                inc_egress_drop(pslot, bytes);
                inc_rule(matched_rule);
                return TC_ACT_SHOT;
            }
            if ((bv->proto == 0 || bv->proto == proto) && (bv->port == 0 || bv->port == dport)) {
                matched_rule = bv->rule_id;
                inc(7);
                inc_egress_drop(pslot, bytes);
                inc_rule(matched_rule);
                return TC_ACT_SHOT;
            }
        }
    }

    if (dport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk_dport = ((__u32)proto << 16) | dport;
        __u32 pk_any = (__u32)dport;
        struct wl_val *bp = bl_out_port.lookup(&pk_dport);
        if (!bp) bp = bl_out_port.lookup(&pk_any);
        if (bp && bp->action == 1) {
            matched_rule = bp->rule_id;
            inc(7);
            inc_egress_drop(pslot, bytes);
            inc_rule(matched_rule);
            return TC_ACT_SHOT;
        }
    }

    if (sport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk_sport = (1 << 24) | ((__u32)proto << 16) | sport;
        __u32 pk_any_s = (1 << 24) | (__u32)sport;
        struct wl_val *bp = bl_out_port.lookup(&pk_sport);
        if (!bp) bp = bl_out_port.lookup(&pk_any_s);
        if (bp && bp->action == 1) {
            matched_rule = bp->rule_id;
            inc(7);
            inc_egress_drop(pslot, bytes);
            inc_rule(matched_rule);
            return TC_ACT_SHOT;
        }
    }

    __u64 now = bpf_ktime_get_ns();
    struct ct_val *existing = conntrack.lookup(&key);
    if (existing) {
        existing->last_seen = now;
        if (new_state == CT_EST && existing->state == CT_NEW) existing->state = CT_EST;
    } else {
        struct ct_val val = {};
        val.last_seen = now;
        val.created = now;
        val.state = new_state;
        conntrack.update(&key, &val);
    }

    inc(6);
    inc_egress(pslot, bytes);
    return TC_ACT_OK;
}

int xdp_firewall(struct xdp_md *ctx) {
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 pkt_bytes = (__u32)(end - data);
    __u32 src_be = 0;
    __u8 proto = 0;
    int pslot = 3;
    __u32 matched_rule = 0;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) goto drop;
    if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        int z6 = 0;
        __u8 *v6p = ipv6_policy.lookup(&z6);
        if (!v6p || *v6p == 0) {
            inc(8);
            goto drop;
        }
        goto pass;
    }
    if (eth->h_proto != __constant_htons(ETH_P_IP)) goto pass;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end || ip->ihl < 5) goto drop;

    src_be = ip->saddr;
    __u32 dst_be = ip->daddr;
    proto = ip->protocol;
    pslot = proto_slot(proto);
    __u16 dport = 0;
    __u16 sport = 0;
    __u16 dport_be = 0;
    __u16 sport_be = 0;
    __u16 icmp_id_be = 0;
    __u8 icmp_type = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    __u8 b0 = (src_be >> 0) & 0xFF;
    if (b0 == 127) goto pass;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > end) goto drop;
        dport = __be16_to_cpu(tcp->dest);
        sport = __be16_to_cpu(tcp->source);
        dport_be = tcp->dest;
        sport_be = tcp->source;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > end) goto drop;
        dport = __be16_to_cpu(udp->dest);
        sport = __be16_to_cpu(udp->source);
        dport_be = udp->dest;
        sport_be = udp->source;
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if ((void *)(icmp + 1) > end) goto drop;
        icmp_type = icmp->type;
        dport = ((__u16)icmp->type << 8) | icmp->code;
        icmp_id_be = icmp->un.echo.id;
    }

    {
        struct lpm_key bk = { .prefixlen = 32, .addr = src_be };
        struct wl_val *bv = bl_subnet.lookup(&bk);
        if (bv && bv->action == 1) {
            if (bv->proto == 0 && bv->port == 0) {
                matched_rule = bv->rule_id;
                inc(3);
                goto drop;
            }
            if ((bv->proto == 0 || bv->proto == proto) && (bv->port == 0 || bv->port == dport)) {
                matched_rule = bv->rule_id;
                inc(3);
                goto drop;
            }
        }
    }

    if (dport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk_proto = ((__u32)proto << 16) | dport;
        __u32 pk_any = (__u32)dport;
        struct wl_val *bp = bl_port.lookup(&pk_proto);
        if (!bp) bp = bl_port.lookup(&pk_any);
        if (bp && bp->action == 1) {
            matched_rule = bp->rule_id;
            inc(3);
            goto drop;
        }
    }

    if (sport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk_proto_s = (1 << 24) | ((__u32)proto << 16) | sport;
        __u32 pk_any_s = (1 << 24) | (__u32)sport;
        struct wl_val *bp = bl_port.lookup(&pk_proto_s);
        if (!bp) bp = bl_port.lookup(&pk_any_s);
        if (bp && bp->action == 1) {
            matched_rule = bp->rule_id;
            inc(3);
            goto drop;
        }
    }

    if (dport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk = ((__u32)proto << 16) | dport;
        __u32 *lim = rl_port_cfg.lookup(&pk);
        if (lim && *lim > 0) {
            if (check_port_rl(pk)) {
                __u32 *rid = rl_port_rule.lookup(&pk);
                if (rid) matched_rule = *rid;
                inc(2);
                goto drop;
            }
        }
        if (!lim) {
            __u32 pw = (__u32)dport;
            __u32 *lim2 = rl_port_cfg.lookup(&pw);
            if (lim2 && *lim2 > 0) {
                if (check_port_rl(pw)) {
                    __u32 *rid = rl_port_rule.lookup(&pw);
                    if (rid) matched_rule = *rid;
                    inc(2);
                    goto drop;
                }
            }
        }
        if (check_per_ip_rl(src_be, pk)) {
            __u32 *rid = per_ip_port_rule.lookup(&pk);
            if (rid) matched_rule = *rid;
            inc(2);
            goto drop;
        }
    }

    if (sport != 0 && proto != IPPROTO_ICMP) {
        __u32 pk_s = (1 << 24) | ((__u32)proto << 16) | sport;
        __u32 *lim_s = rl_port_cfg.lookup(&pk_s);
        if (lim_s && *lim_s > 0) {
            if (check_port_rl(pk_s)) {
                __u32 *rid = rl_port_rule.lookup(&pk_s);
                if (rid) matched_rule = *rid;
                inc(2);
                goto drop;
            }
        }
        if (!lim_s) {
            __u32 pw_s = (1 << 24) | (__u32)sport;
            __u32 *lim2_s = rl_port_cfg.lookup(&pw_s);
            if (lim2_s && *lim2_s > 0) {
                if (check_port_rl(pw_s)) {
                    __u32 *rid = rl_port_rule.lookup(&pw_s);
                    if (rid) matched_rule = *rid;
                    inc(2);
                    goto drop;
                }
            }
        }
        if (check_per_ip_rl(src_be, pk_s)) {
            __u32 *rid = per_ip_port_rule.lookup(&pk_s);
            if (rid) matched_rule = *rid;
            inc(2);
            goto drop;
        }
    }

    if (proto == IPPROTO_ICMP) {
        __u8 icmp_proto = IPPROTO_ICMP;
        if (check_proto_rl(icmp_proto)) {
            __u32 *rid = rl_proto_rule.lookup(&icmp_proto);
            if (rid) matched_rule = *rid;
            inc(2);
            inc(4);
            goto drop;
        }
    }

    if (ct_enabled()) {
        struct ct_key rkey = {};
        rkey.local_ip = dst_be;
        rkey.remote_ip = src_be;
        rkey.proto = proto;
        int do_ct = 0;

        if (proto == IPPROTO_TCP) {
            rkey.local_port = dport_be;
            rkey.remote_port = sport_be;
            do_ct = 1;
        } else if (proto == IPPROTO_UDP) {
            rkey.local_port = dport_be;
            rkey.remote_port = sport_be;
            do_ct = 1;
        } else if (proto == IPPROTO_ICMP && icmp_type == 0) {
            rkey.local_port = icmp_id_be;
            rkey.remote_port = 0;
            do_ct = 1;
        } else if (proto != IPPROTO_ICMP) {
            rkey.local_port = dport_be;
            rkey.remote_port = sport_be;
            do_ct = 1;
        }

        if (do_ct) {
            struct ct_val *ct = conntrack.lookup(&rkey);
            if (ct) {
                __u64 now = bpf_ktime_get_ns();
                __u64 to = ct_timeout(proto, ct->state);
                int expired = 0;
                int z = 0;
                __u64 *max_age = conn_timeout_cfg.lookup(&z);
                if (now - ct->last_seen >= to) expired = 1;
                if (max_age && *max_age > 0 && ct->created > 0 && now - ct->created >= *max_age) expired = 1;
                if (!expired) {
                    ct->last_seen = now;
                    if (ct->state == CT_NEW) ct->state = CT_EST;
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
                if (check_subnet_rl(src_be, rv)) {
                    matched_rule = rv->rule_id;
                    inc(2);
                    goto drop;
                }
                matched_rule = rv->rule_id;
                goto pass;
            }
            if ((rv->proto == 0 || rv->proto == proto) && (rv->port == 0 || rv->port == dport)) {
                if (check_subnet_rl(src_be, rv)) {
                    matched_rule = rv->rule_id;
                    inc(2);
                    goto drop;
                }
                matched_rule = rv->rule_id;
                goto pass;
            }
        }
    }

    if (proto == IPPROTO_UDP && (dport == 53 || sport == 53)) {
        __u8 is_resp = (sport == 53) ? 1 : 0;
        __u8 dns_key = is_resp ? 1 : 0;
        __u8 *dns_allowed = dns_wl.lookup(&dns_key);
        __u32 *dns_rid = dns_rule.lookup(&dns_key);
        if (dns_allowed && *dns_allowed == 1) {
            if (dns_rid) matched_rule = *dns_rid;
            if (check_dns_rl(src_be, is_resp)) {
                inc(2);
                goto drop;
            }
            goto pass;
        }
        __u8 dns_any_key = 2;
        __u8 *dns_any = dns_wl.lookup(&dns_any_key);
        __u32 *dns_any_rid = dns_rule.lookup(&dns_any_key);
        if (dns_any && *dns_any == 1) {
            if (dns_any_rid) matched_rule = *dns_any_rid;
            if (check_dns_rl(src_be, is_resp)) {
                inc(2);
                goto drop;
            }
            goto pass;
        }
    }

    if (check_global()) {
        int z = 0;
        __u32 *rid = rl_global_rule.lookup(&z);
        if (rid) matched_rule = *rid;
        inc(2);
        goto drop;
    }

    if (proto != IPPROTO_ICMP && check_proto_rl(proto)) {
        __u32 *rid = rl_proto_rule.lookup(&proto);
        if (rid) matched_rule = *rid;
        inc(2);
        goto drop;
    }

    {
        __u32 rid_ip = 0;
        if (check_ip_rl(src_be, &rid_ip)) {
            if (rid_ip) matched_rule = rid_ip;
            inc(2);
            goto drop;
        }
    }

    if (proto == IPPROTO_ICMP) {
        __u16 tc = dport;
        __u16 tc_any = (dport & 0xFF00) | 0xFF;
        __u16 all = 0xFFFF;
        struct wl_val *iv = wl_icmp.lookup(&tc);
        if (!iv) iv = wl_icmp.lookup(&tc_any);
        if (!iv) iv = wl_icmp.lookup(&all);
        if (iv && iv->action == 1) {
            matched_rule = iv->rule_id;
            __u32 icmp_rl_key = ((__u32)IPPROTO_ICMP << 16) | iv->port;
            if (iv->rate_limit > 0 && check_port_rl(icmp_rl_key)) {
                inc(2);
                goto drop;
            }
            if (check_per_ip_rl(src_be, icmp_rl_key)) {
                inc(2);
                goto drop;
            }
            goto pass;
        }
        inc(4);
        goto drop;
    }

    if (dport != 0) {
        __u32 pk = ((__u32)proto << 16) | dport;
        struct wl_val *p = wl_port.lookup(&pk);
        if (p && p->action == 1) {
            if (p->rate_limit > 0 && check_port_rl(pk)) {
                matched_rule = p->rule_id;
                inc(2);
                goto drop;
            }
            matched_rule = p->rule_id;
            goto pass;
        }
        __u32 pw = dport;
        struct wl_val *p2 = wl_port.lookup(&pw);
        if (p2 && p2->action == 1) {
            if (p2->rate_limit > 0 && check_port_rl(pw)) {
                matched_rule = p2->rule_id;
                inc(2);
                goto drop;
            }
            matched_rule = p2->rule_id;
            goto pass;
        }
    }

    if (sport != 0) {
        __u32 pk = (1 << 24) | ((__u32)proto << 16) | sport;
        struct wl_val *p = wl_port.lookup(&pk);
        if (p && p->action == 1) {
            if (p->rate_limit > 0 && check_port_rl(pk)) {
                matched_rule = p->rule_id;
                inc(2);
                goto drop;
            }
            matched_rule = p->rule_id;
            goto pass;
        }
        __u32 pw = (1 << 24) | (__u32)sport;
        struct wl_val *p2 = wl_port.lookup(&pw);
        if (p2 && p2->action == 1) {
            if (p2->rate_limit > 0 && check_port_rl(pw)) {
                matched_rule = p2->rule_id;
                inc(2);
                goto drop;
            }
            matched_rule = p2->rule_id;
            goto pass;
        }
    }

drop:
    inc(1);
    inc_proto(pslot, 1, pkt_bytes);
    if (matched_rule) {
        inc_rule(matched_rule);
        inc_rule_drop(matched_rule);
    }
    return XDP_DROP;

pass:
    inc(0);
    inc_proto(pslot, 0, pkt_bytes);
    if (matched_rule) {
        inc_rule(matched_rule);
        inc_rule_pass(matched_rule);
    }
    return XDP_PASS;
}
