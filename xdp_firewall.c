#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// BPF map definitions (using new BTF-based format)
#define SEC(NAME) __attribute__((section(NAME), used))

#define MAX_ENTRIES 65536
#define MAX_PORTS 256

// Configuration structure
struct config {
    __u32 per_ip_pps_limit;
    __u32 per_ip_syn_pps_limit;
    __u32 per_ip_udp_pps_limit;
    __u64 per_ip_udp_bps_limit;
    __u64 per_ip_bps_limit;
    
    __u32 per_flow_pps_limit;
    __u32 per_flow_syn_pps_limit;
    __u32 per_flow_udp_pps_limit;
    __u64 per_flow_udp_bps_limit;
    __u64 per_flow_bps_limit;
    
    __u8 per_ip_action;   // 0 = pass, 1 = drop
    __u8 per_flow_action; // 0 = pass, 1 = drop
};

// Per-IP rate tracking
struct ip_stats {
    __u64 last_update;
    __u32 pps_count;
    __u32 syn_pps_count;
    __u32 udp_pps_count;
    __u64 udp_bps_count;
    __u64 bps_count;
};

// Flow key structure
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 pad[3];
} __attribute__((packed));

// Per-flow rate tracking
struct flow_stats {
    __u64 last_update;
    __u32 pps_count;
    __u32 syn_pps_count;
    __u32 udp_pps_count;
    __u64 udp_bps_count;
    __u64 bps_count;
};

// Global statistics
struct global_stats {
    __u64 packets_passed;
    __u64 packets_dropped;
    __u64 per_ip_pps_hits;
    __u64 per_ip_syn_pps_hits;
    __u64 per_ip_udp_pps_hits;
    __u64 per_ip_udp_bps_hits;
    __u64 per_ip_bps_hits;
    __u64 per_flow_pps_hits;
    __u64 per_flow_syn_pps_hits;
    __u64 per_flow_udp_pps_hits;
    __u64 per_flow_udp_bps_hits;
    __u64 per_flow_bps_hits;
    __u64 whitelist_hits;
    __u64 blacklist_hits;
    __u64 current_pps;
    __u64 current_bps;
    __u64 last_stat_update;
};

// CIDR entry
struct cidr_entry {
    __u32 addr;
    __u32 mask;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct ip_stats);
} ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct cidr_entry);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct cidr_entry);
} blacklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u32);
    __type(value, __u16);
} ports_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats);
} stats_map SEC(".maps");

// Helper to get current time in nanoseconds
static __always_inline __u64 get_time_ns(void)
{
    return bpf_ktime_get_ns();
}

// Check if IP matches CIDR entry
static __always_inline int ip_matches_cidr(__u32 ip, struct cidr_entry *cidr)
{
    return (ip & cidr->mask) == cidr->addr;
}

// Check whitelist
static __always_inline int is_whitelisted(__u32 src_ip)
{
    struct cidr_entry *entry;
    __u32 key;
    
    // Check exact match first
    entry = bpf_map_lookup_elem(&whitelist_map, &src_ip);
    if (entry && ip_matches_cidr(src_ip, entry)) {
        return 1;
    }
    
    // Iterate through whitelist (limited loop)
    #pragma unroll
    for (key = 0; key < 64; key++) {
        entry = bpf_map_lookup_elem(&whitelist_map, &key);
        if (entry && ip_matches_cidr(src_ip, entry)) {
            return 1;
        }
    }
    
    return 0;
}

// Check blacklist
static __always_inline int is_blacklisted(__u32 src_ip)
{
    struct cidr_entry *entry;
    __u32 key;
    
    // Check exact match first
    entry = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (entry && ip_matches_cidr(src_ip, entry)) {
        return 1;
    }
    
    // Iterate through blacklist (limited loop)
    #pragma unroll
    for (key = 0; key < 64; key++) {
        entry = bpf_map_lookup_elem(&blacklist_map, &key);
        if (entry && ip_matches_cidr(src_ip, entry)) {
            return 1;
        }
    }
    
    return 0;
}

// Check if port is protected
static __always_inline int is_port_protected(__u16 port)
{
    __u32 key;
    __u16 *protected_port;
    
    #pragma unroll
    for (key = 0; key < MAX_PORTS; key++) {
        protected_port = bpf_map_lookup_elem(&ports_map, &key);
        if (protected_port && *protected_port == port) {
            return 1;
        }
        if (protected_port && *protected_port == 0) {
            break;
        }
    }
    
    return 0;
}

// Update per-IP stats and check limits
static __always_inline int check_per_ip_limits(
    struct config *cfg,
    __u32 src_ip,
    __u64 now,
    int is_syn,
    int is_udp,
    __u32 packet_size,
    struct global_stats *gstats)
{
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_map, &src_ip);
    struct ip_stats new_stats = {0};
    __u64 time_diff_ns;
    
    if (!stats) {
        new_stats.last_update = now;
        new_stats.pps_count = 1;
        new_stats.syn_pps_count = is_syn ? 1 : 0;
        new_stats.udp_pps_count = is_udp ? 1 : 0;
        new_stats.udp_bps_count = is_udp ? packet_size : 0;
        new_stats.bps_count = packet_size;
        bpf_map_update_elem(&ip_map, &src_ip, &new_stats, BPF_ANY);
        return 0; // pass
    }
    
    time_diff_ns = now - stats->last_update;
    
    // Reset counters if more than 1 second has passed
    if (time_diff_ns >= 1000000000ULL) {
        stats->last_update = now;
        stats->pps_count = 1;
        stats->syn_pps_count = is_syn ? 1 : 0;
        stats->udp_pps_count = is_udp ? 1 : 0;
        stats->udp_bps_count = is_udp ? packet_size : 0;
        stats->bps_count = packet_size;
        bpf_map_update_elem(&ip_map, &src_ip, stats, BPF_ANY);
        return 0; // pass
    }
    
    // Check limits
    if (cfg->per_ip_pps_limit > 0 && stats->pps_count >= cfg->per_ip_pps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_ip_pps_hits, 1);
        return cfg->per_ip_action == 1 ? 1 : 0;
    }
    
    if (is_syn && cfg->per_ip_syn_pps_limit > 0 && stats->syn_pps_count >= cfg->per_ip_syn_pps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_ip_syn_pps_hits, 1);
        return cfg->per_ip_action == 1 ? 1 : 0;
    }
    
    if (is_udp && cfg->per_ip_udp_pps_limit > 0 && stats->udp_pps_count >= cfg->per_ip_udp_pps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_ip_udp_pps_hits, 1);
        return cfg->per_ip_action == 1 ? 1 : 0;
    }
    
    if (is_udp && cfg->per_ip_udp_bps_limit > 0 && stats->udp_bps_count >= cfg->per_ip_udp_bps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_ip_udp_bps_hits, 1);
        return cfg->per_ip_action == 1 ? 1 : 0;
    }
    
    if (cfg->per_ip_bps_limit > 0 && stats->bps_count >= cfg->per_ip_bps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_ip_bps_hits, 1);
        return cfg->per_ip_action == 1 ? 1 : 0;
    }
    
    // Update counters
    stats->pps_count++;
    if (is_syn) stats->syn_pps_count++;
    if (is_udp) {
        stats->udp_pps_count++;
        stats->udp_bps_count += packet_size;
    }
    stats->bps_count += packet_size;
    
    bpf_map_update_elem(&ip_map, &src_ip, stats, BPF_ANY);
    return 0; // pass
}

// Update per-flow stats and check limits
static __always_inline int check_per_flow_limits(
    struct config *cfg,
    struct flow_key *key,
    __u64 now,
    int is_syn,
    int is_udp,
    __u32 packet_size,
    struct global_stats *gstats)
{
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_map, key);
    struct flow_stats new_stats = {0};
    __u64 time_diff_ns;
    
    if (!stats) {
        new_stats.last_update = now;
        new_stats.pps_count = 1;
        new_stats.syn_pps_count = is_syn ? 1 : 0;
        new_stats.udp_pps_count = is_udp ? 1 : 0;
        new_stats.udp_bps_count = is_udp ? packet_size : 0;
        new_stats.bps_count = packet_size;
        bpf_map_update_elem(&flow_map, key, &new_stats, BPF_ANY);
        return 0; // pass
    }
    
    time_diff_ns = now - stats->last_update;
    
    // Reset counters if more than 1 second has passed
    if (time_diff_ns >= 1000000000ULL) {
        stats->last_update = now;
        stats->pps_count = 1;
        stats->syn_pps_count = is_syn ? 1 : 0;
        stats->udp_pps_count = is_udp ? 1 : 0;
        stats->udp_bps_count = is_udp ? packet_size : 0;
        stats->bps_count = packet_size;
        bpf_map_update_elem(&flow_map, key, stats, BPF_ANY);
        return 0; // pass
    }
    
    // Check limits
    if (cfg->per_flow_pps_limit > 0 && stats->pps_count >= cfg->per_flow_pps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_flow_pps_hits, 1);
        return cfg->per_flow_action == 1 ? 1 : 0;
    }
    
    if (is_syn && cfg->per_flow_syn_pps_limit > 0 && stats->syn_pps_count >= cfg->per_flow_syn_pps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_flow_syn_pps_hits, 1);
        return cfg->per_flow_action == 1 ? 1 : 0;
    }
    
    if (is_udp && cfg->per_flow_udp_pps_limit > 0 && stats->udp_pps_count >= cfg->per_flow_udp_pps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_flow_udp_pps_hits, 1);
        return cfg->per_flow_action == 1 ? 1 : 0;
    }
    
    if (is_udp && cfg->per_flow_udp_bps_limit > 0 && stats->udp_bps_count >= cfg->per_flow_udp_bps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_flow_udp_bps_hits, 1);
        return cfg->per_flow_action == 1 ? 1 : 0;
    }
    
    if (cfg->per_flow_bps_limit > 0 && stats->bps_count >= cfg->per_flow_bps_limit) {
        if (gstats) __sync_fetch_and_add(&gstats->per_flow_bps_hits, 1);
        return cfg->per_flow_action == 1 ? 1 : 0;
    }
    
    // Update counters
    stats->pps_count++;
    if (is_syn) stats->syn_pps_count++;
    if (is_udp) {
        stats->udp_pps_count++;
        stats->udp_bps_count += packet_size;
    }
    stats->bps_count += packet_size;
    
    bpf_map_update_elem(&flow_map, key, stats, BPF_ANY);
    return 0; // pass
}

SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    __u32 key = 0;
    struct config *cfg;
    struct global_stats *gstats;
    struct flow_key fkey = {0};
    __u64 now;
    __u32 packet_size;
    int is_syn = 0;
    int is_udp = 0;
    __u16 dst_port = 0;
    
    // Parse Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    packet_size = bpf_ntohs(ip->tot_len);
    now = get_time_ns();
    
    // Get configuration
    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return XDP_PASS;
    
    // Get stats
    gstats = bpf_map_lookup_elem(&stats_map, &key);
    
    // Check blacklist
    if (is_blacklisted(ip->saddr)) {
        if (gstats) {
            __sync_fetch_and_add(&gstats->blacklist_hits, 1);
            __sync_fetch_and_add(&gstats->packets_dropped, 1);
        }
        return XDP_DROP;
    }
    
    // Check whitelist
    if (is_whitelisted(ip->saddr)) {
        if (gstats) {
            __sync_fetch_and_add(&gstats->whitelist_hits, 1);
            __sync_fetch_and_add(&gstats->packets_passed, 1);
        }
        return XDP_PASS;
    }
    
    // Parse transport layer
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        dst_port = bpf_ntohs(tcp->dest);
        is_syn = (tcp->syn && !tcp->ack);
        
        fkey.src_port = bpf_ntohs(tcp->source);
        fkey.dst_port = dst_port;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        dst_port = bpf_ntohs(udp->dest);
        is_udp = 1;
        
        fkey.src_port = bpf_ntohs(udp->source);
        fkey.dst_port = dst_port;
    } else {
        // Pass non-TCP/UDP traffic
        if (gstats) __sync_fetch_and_add(&gstats->packets_passed, 1);
        return XDP_PASS;
    }
    
    // Check if port is protected
    if (!is_port_protected(dst_port)) {
        if (gstats) __sync_fetch_and_add(&gstats->packets_passed, 1);
        return XDP_PASS;
    }
    
    // Set flow key
    fkey.src_ip = ip->saddr;
    fkey.dst_ip = ip->daddr;
    fkey.proto = ip->protocol;
    
    // Check per-IP limits
    if (check_per_ip_limits(cfg, ip->saddr, now, is_syn, is_udp, packet_size, gstats)) {
        if (gstats) __sync_fetch_and_add(&gstats->packets_dropped, 1);
        return XDP_DROP;
    }
    
    // Check per-flow limits
    if (check_per_flow_limits(cfg, &fkey, now, is_syn, is_udp, packet_size, gstats)) {
        if (gstats) __sync_fetch_and_add(&gstats->packets_dropped, 1);
        return XDP_DROP;
    }
    
    // Update global stats
    if (gstats) __sync_fetch_and_add(&gstats->packets_passed, 1);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

