# Improving The Effectiveness of Traffic Engineering by Including Remaining Amount of Data and Time to Send in TCP Packets

## Members
- Li Yuan-Cai  
- Lian Jia-Yao  
- Yang Jhen-Yu  

---

## Research Motivation
With the increasing diversity of network applications, managing data flows with different characteristics has become a central challenge in network optimization. P4 (Programming Protocol-Independent Packet Processors) enables programmable switches to dynamically adjust routing strategies and achieve precise load balancing.  
However, in practice, a critical issue arises: **control latency**.

Specifically, the process from detecting network congestion to updating routing rules in the P4 controller introduces non-negligible delay. For very short-lived traffic (mouse flows), this delay often renders control decisions ineffective—by the time the new rule is installed, the flow has already completed, making the control effort meaningless.

The motivation of this work is to resolve this timing mismatch by designing a more **real-time responsive routing adjustment mechanism**. Our goal is to enable flow management in P4 to effectively balance the needs of both short and long flows, thereby improving overall network performance and resource utilization.

---

## Research Method
We customized **five 32-bit unsigned tuples** in the TCP header options to store flow-specific information:

1. **total_time** – The estimated total time required for transmission.  
2. **elapsed_time** – Time elapsed since the start of transmission (ms).  
3. **total_size** – The total number of bytes expected to be transmitted.  
4. **sent_size** – The number of bytes already transmitted since the start.  
5. **estimated_remaining_time** – Estimated remaining transmission time, calculated from progress and elapsed time (or by subtracting elapsed_time from total_time).  

These fields are inserted into the TCP header by modifying the Linux kernel source code. Transmission experiments were then conducted in a Mininet environment using a P4 virtual machine.  

---

## Application Scenarios
We consider two scenarios:  

| Tuple                  | File Transfer | Streaming |
|-------------------------|---------------|-----------|
| total_time              |               | ✔         |
| elapsed_time            | ✔             | ✔         |
| total_size              | ✔             |           |
| sent_size               | ✔             | ✔         |
| estimated_remaining_time| ✔             | ✔         |

- **File Transfer**: Concerned with total file size.  
- **Streaming**: Concerned with time duration.  

---

## Implementation Details
To enable these tuples to be parsed by the P4 controller during TCP transmission, we embedded them into the TCP option field. This required modifying the Linux kernel and rebooting the system.  

- Kernel modification: [change of Linux kernel](./linux-6.1.93)  
- Validation with simple topology & test files: [TCP option test](./test_tcp_option)  

The experiments confirmed successful embedding of the tuples.  

---

## Algorithm Comparison (Unfinished)
We implemented multiple algorithms to evaluate performance improvements when utilizing the five custom tuples.  
Using **BFS** as the baseline, we compared the results of other algorithms.  

- Detailed process: [Send-time testing](./test_sendtime)  

---

## Packet_in Implementation (Unfinished)
We attempted to implement **packet_in** functionality in the P4 controller to actively notify about flow-related events.  
This module is still **under development** and not yet complete.  

- Source folder: [packet_in](./packet_in)  

---

## Conclusion
By embedding custom flow information tuples into TCP options and leveraging P4 programmable switches, we demonstrate a framework for more responsive traffic engineering. This approach reduces the mismatch between controller decision latency and flow lifetimes, particularly benefiting short-lived flows.
