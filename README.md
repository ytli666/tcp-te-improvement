<h1 align="center" style="font-size: 42px;">
Design and Implementation of a P4-Based Traffic Engineering System with Custom TCP Options
</h1>

##  Research Motivation
When downloading or transmitting many files on a computer, the transmission speed often becomes slow due to congestion.  
To address this issue, we explored solutions in the field of **Traffic Engineering (TE)**.  
After discussion with our advisor, we decided to focus on **P4-based Traffic Engineering using custom TCP options**.

##  Research Process
1. **Learning P4 Language**
   - Before diving into research, we first studied the syntax and features of P4.
   - We practiced with **13 exercises** from the official P4 tutorials, covering basic applications and programming methods.  
   👉 [P4 Tutorials Exercises](https://github.com/p4lang/tutorials/tree/master/exercises)

2. **Custom TCP Options**
   - Added **5 custom tuples** in the TCP option field.
   - Rebuilt the Linux kernel to integrate these new options.
   - Designed a method to use the **5-tuple information** for traffic engineering tasks such as flow management and optimization.

3. **Implementation Stage**
   - Currently in the final experimental stage.
   - The system is still under development (work in progress).

##  About P4 Language
- **P4 (Programming Protocol-Independent Packet Processors)** is a domain-specific language designed for programming packet processors.
- It enables fine-grained control over how network devices process packets, making it ideal for **Traffic Engineering** research.

## 📚 Learning Resources
- [P4 Tutorials (GitHub)](https://github.com/p4lang/tutorials)  
- [Exercises Repository](https://github.com/p4lang/tutorials/tree/master/exercises)  

##  Project Status
🚧 **Work in Progress**  
This project started in our 3rd year (junior year) and is still ongoing. Final results will be updated here.

