/* Kernel-wire fixture: translate aggregates with TCP options and short tails. */
#include "tayga.h"
#include "gso.h"
#include "stats.h"
#include <assert.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
_Atomic time_t now;
int main(void)
{
    assert(config_init() == 0); stats_init();
    gcfg.wkpf_strict = 0; gcfg.cache_size = 0; gcfg.maps_immutable = 1; gcfg.vnet_hdr_sz = 10; gcfg.mtu = 1500;
    struct map_static map = {0}, prefix = {0};
    INIT_LIST_HEAD(&map.map4.list); INIT_LIST_HEAD(&map.map6.list);
    INIT_LIST_HEAD(&prefix.map4.list); INIT_LIST_HEAD(&prefix.map6.list);
    map.map4.type = map.map6.type = MAP_TYPE_STATIC;
    map.map4.prefix_len = 32; map.map6.prefix_len = 128;
    inet_pton(AF_INET,"192.0.2.2",&map.map4.addr);
    inet_pton(AF_INET6,"2001:db8::2",&map.map6.addr);
    calc_ip4_mask(&map.map4.mask,NULL,32);calc_ip6_mask(&map.map6.mask,NULL,128);
    assert(insert_map4(&map.map4,NULL)==0 && insert_map6(&map.map6,NULL)==0);
    prefix.map4.type=prefix.map6.type=MAP_TYPE_RFC6052;prefix.map6.prefix_len=96;
    inet_pton(AF_INET6,"64:ff9b::",&prefix.map6.addr);calc_ip6_mask(&prefix.map6.mask,NULL,96);
    assert(insert_map4(&prefix.map4,NULL)==0 && insert_map6(&prefix.map6,NULL)==0);
    int fd=open("/dev/net/tun",O_RDWR);assert(fd>=0);
    struct ifreq req={0};strcpy(req.ifr_name,"tailtun");
    req.ifr_flags=IFF_TUN|IFF_NO_PI|IFF_VNET_HDR;
    assert(ioctl(fd,TUNSETIFF,&req)==0);
    int size=10;assert(ioctl(fd,TUNSETVNETHDRSZ,&size)==0);
    assert(ioctl(fd,TUNSETOFFLOAD,TUN_F_CSUM|TUN_F_TSO4|TUN_F_TSO6)==0);
    puts("READY");fflush(stdout);assert(getchar()=='G');
    const unsigned headers[]={20,32,60};
    for(unsigned h=0;h<3;h++) for(unsigned full=1;full<=2;full++) for(unsigned tail=1;tail<=3;tail++) {
        unsigned tcp_header_len=headers[h];
        unsigned payload_len=full*1400+(tail==3 ? 1260-20-tcp_header_len : tail);
        uint8_t *storage=calloc(1,HEADROOM+40+tcp_header_len+payload_len);assert(storage);
        struct ip6 *ip=(void *)(storage+HEADROOM);struct tcp_hdr *tcp=(void *)(ip+1);
        ip->ver_tc_fl=htonl(0x60000000);ip->payload_length=htons(tcp_header_len+payload_len);
        ip->next_header=IPPROTO_TCP;ip->hop_limit=64;
        inet_pton(AF_INET6,"2001:db8::2",&ip->src);
        inet_pton(AF_INET6,"64:ff9b::c633:6402",&ip->dest);
        tcp->src_port=htons(6000+h*100+full*10+tail);tcp->dst_port=htons(7000);tcp->seq=htonl(1000);
        tcp->doff_res=(tcp_header_len/4)<<4;tcp->flags=TCP_FLAG_ACK|TCP_FLAG_PSH|TCP_FLAG_FIN|TCP_FLAG_CWR;
        if(tcp_header_len>=32) {
            uint8_t *options=(uint8_t *)tcp+20;
            options[0]=options[1]=1;options[2]=8;options[3]=10;
            uint32_t timestamp=htonl(1000);memcpy(options+4,&timestamp,4);memcpy(options+8,&timestamp,4);
        }
        for(unsigned n=0;n<payload_len;n++) ((uint8_t *)tcp+tcp_header_len)[n]=(uint8_t)(n%251);
        tcp->cksum=htons(gso_calc_tcp_pseudo6(&ip->src,&ip->dest,tcp_header_len+payload_len));
        struct pkt p={.tun_fd=fd,.data=(void *)ip,.data_len=40+tcp_header_len+payload_len,.has_vhdr=1,
            .vhdr={.flags=VIRTIO_NET_HDR_F_NEEDS_CSUM,.gso_type=VIRTIO_NET_HDR_GSO_TCPV6|VIRTIO_NET_HDR_GSO_ECN,
                .hdr_len=40+tcp_header_len,.gso_size=1400,.csum_start=40,.csum_offset=16}};
        assert(gso_translate_tcp_6to4(&p)==0);free(storage);
    }
    struct tayga_stats stats;stats_flush_worker();stats_get_snapshot(&stats);
    assert(stats.gso_split_tail_pkts == 18 && stats.gso_tun_write_errors == 0 && stats.gso_tx_pkts == 36);
    fprintf(stderr,"fixture: split=%llu write_errors=%llu tx=%llu\n",
        (unsigned long long)stats.gso_split_tail_pkts,(unsigned long long)stats.gso_tun_write_errors,
        (unsigned long long)stats.gso_tx_pkts);
    assert(getchar()=='Q');close(fd);return 0;
}
