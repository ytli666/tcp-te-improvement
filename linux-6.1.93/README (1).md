# flow-info-kernel
### 實作內容
下載 Linux kernel，並更改以下的檔案：

**include/uapi/linux/tcp.h**

~~~c
#define TCP_FLOW_INFO 1001

#ifndef _UAPI_TCP_FLOW_INFO_H
#define _UAPI_TCP_FLOW_INFO_H

struct tcp_flow_info {
    __u32 total_time;
    __u32 elapsed_time;
    __u32 total_size;
    __u32 sent_size;
    __u32 estimated_remaining_time;
};
#endif
~~~

**include/linux/tcp.h**

在struct tcp_sock中增加struct tcp_flow_info *flow_info;

**include/net/tcp.h**

~~~c
#define TCPOPT_FLOW_INFO 253
#define TCPOLEN_FLOW_INFO 22
~~~

**net/ipv4/tcp.c**

於tcp_init_sock()、__tcp_close()、do_tcp_setsockopt()及do_tcp_getsockopt()增加自訂的option實作

**net/ipv4/tcp_output.c**

~~~c
#define OPTION_FLOW_INFO BIT(15)
~~~

於struct tcp_out_options中新增struct tcp_flow_info *flow_info

於tcp_options_write()與tcp_established_options增加自訂的option實作

**net/ipv4/tcp_input.c**

於tcp_parse_options()增加自訂的option(未實作)

### 使用須知

欲使用自訂option時請在檔案中增加如下定義

~~~c
#define TCP_FLOW_INFO 1001  // 自訂的 option number，跟 kernel 對應

struct tcp_flow_info {
    uint32_t total_time;
    uint32_t elapsed_time;
    uint32_t total_size;
    uint32_t sent_size;
    uint32_t estimated_remaining_time;
};
~~~

### 套用方式
更改完之後重新 **reboot Linux kernel**，並套用到 **P4 虛擬機** 中。