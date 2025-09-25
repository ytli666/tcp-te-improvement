# flow-info-kernel

### Implementation Details
Download the Linux kernel and modify the following files:

**include/uapi/linux/tcp.h**

```c
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
```

**include/linux/tcp.h**

Add `struct tcp_flow_info *flow_info;` to `struct tcp_sock`.

**include/net/tcp.h**

```c
#define TCPOPT_FLOW_INFO 253
#define TCPOLEN_FLOW_INFO 22
```

**net/ipv4/tcp.c**

Add custom option implementation in `tcp_init_sock()`, `__tcp_close()`, `do_tcp_setsockopt()`, and `do_tcp_getsockopt()`.

**net/ipv4/tcp_output.c**

```c
#define OPTION_FLOW_INFO BIT(15)
```

Add `struct tcp_flow_info *flow_info` to `struct tcp_out_options`.

Add custom option implementation in `tcp_options_write()` and `tcp_established_options`.

**net/ipv4/tcp_input.c**

Add custom option handling in `tcp_parse_options()` (**not implemented yet**).

---

### Notes for Usage

To use the custom option, please add the following definition in your code:

```c
#define TCP_FLOW_INFO 1001  // Custom option number, corresponding to the kernel

struct tcp_flow_info {
    uint32_t total_time;
    uint32_t elapsed_time;
    uint32_t total_size;
    uint32_t sent_size;
    uint32_t estimated_remaining_time;
};
```

---

### Deployment
After making these modifications, **reboot the Linux kernel** and apply it to the **P4 virtual machine**.

---

### Rebuilding the Linux Kernel

**Requirements:**  
- Virtual machine disk space of at least **50 GB**

**Steps:**  
```bash
cp -v /boot/config-$(uname -r) .config
# Edit the .config file as needed
make -j$(nproc)
sudo make modules_install
sudo make install
reboot  # Press ESC during reboot to select the new kernel
```

**Verification:**  
After reboot, confirm the kernel version with:
```bash
uname -r
```
