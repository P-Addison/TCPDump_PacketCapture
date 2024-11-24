# TCPDump_PacketCapture

## Scenario

As a network analyst, I need to use `tcpdump` to capture and analyze live network traffic from a Linux virtual machine.

Here's my task: 
**First**, I'll identify network interfaces to capture network packet data. 
**Second**, I'll use `tcpdump` to filter live network traffic. 
**Third**, I'll capture network traffic using `tcpdump`. 
**Finally**, I'll filter the captured packet data.

## Task 1: Identify Network Interfaces

I need to identify the network interfaces that can be used to capture network packet data. I will do so using the `ifconfig` command.

1. Use `ifconfig` to identify the interfaces that are available:
    ```sh
    sudo ifconfig
    ```

    This command provides output similar to the following:

    ![T1 1](https://github.com/user-attachments/assets/e8eb4f2a-b59b-4a5b-8e40-1684fd1cd965)

    The Ethernet network interface is identified by the entry with the `eth` prefix.

    In this lab, I'll use `eth0` as the interface to capture network packet data in the following tasks.

2. Use `tcpdump` to identify the interface options available for packet capture:
    ```sh
    sudo tcpdump -D
    ```

![T1 2](https://github.com/user-attachments/assets/abc2e21f-f141-46d6-bda9-8ccc95c33e32)

This command will also help identify which network interfaces are available, useful on systems that do not include the `ifconfig` command.

## Task 2: Inspect the Network Traffic of a Network Interface with tcpdump

In this task, I will use `tcpdump` to filter live network packet traffic on an interface.

* Filter live network packet data from the `eth0` interface with `tcpdump`:
    ```sh
    sudo tcpdump -i eth0 -v -c5
    ```

    This command will run `tcpdump` with the following options:
    * `-i eth0`: Capture data specifically from the `eth0` interface.
    * `-v`: Display detailed packet data.
    * `-c5`: Capture 5 packets of data.

Some of my packet traffic data will be similar to the following:

![T2 1](https://github.com/user-attachments/assets/76c27dc2-d1ea-42dd-a73a-df7baefff2c5)

### Exploring Network Packet Details

Using the above example, I'll identify some of the properties that `tcpdump` outputs for the packet capture data I've just seen.

1. At the start of the packet output, `tcpdump` reported that it was listening on the `eth0` interface and provided information on the link type and the capture size in bytes:
    ```sh
    tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
    ```

2. On the next line, the first field is the packet's timestamp, followed by the protocol type, IP:
    ```sh
    22:24:18.910372 IP
    ```

3. The verbose option, `-v`, has provided more details about the IP packet fields, such as TOS, TTL, offset, flags, internal protocol type (in this case, TCP (6)), and the length of the outer IP packet in bytes:
    ```sh
    (tos 0x0, ttl 64, id 5802, offset 0, flags [DF], proto TCP (6), length 134)
    ```

    The specific details about these fields are beyond the scope of this lab, but I should know that these are properties that relate to the IP network packet.

4. In the next section, the data shows the systems that are communicating with each other:
    ```sh
    7acb26dc1f44.5000 > nginx-us-east1-c.c.qwiklabs-terminal-vms-prod-00.internal.59788:
    ```

    By default, `tcpdump` will convert IP addresses into names, as in the screenshot. The name of my Linux virtual machine, also included in the command prompt, appears here as the source for one packet and the destination for the second packet. In my live data, the name will be a different set of letters and numbers.

    The direction of the arrow (`>`) indicates the direction of the traffic flow in this packet. Each system name includes a suffix with the port number (`.5000` in the screenshot), which is used by the source and the destination systems for this packet.

5. The remaining data filters the header data for the inner TCP packet:
    ```sh
    Flags [P.], cksum 0x5851 (incorrect > 0x30d3), seq 1080713945:1080714027, ack 62760789, win 501, options [nop,nop,TS val 1017464119 ecr 3001513453], length 82
    ```

    The flags field identifies TCP flags. In this case, the **P** represents the push flag, and the period indicates it's an ACK flag. This means the packet is pushing out data.

    The next field is the TCP **checksum** value, which is used for detecting errors in the data.

    This section also includes the sequence and acknowledgment numbers, the window size, and the length of the inner TCP packet in bytes.

## Task 3: Capture Network Traffic with tcpdump

In this task, I'll use `tcpdump` to save the captured network data to a packet capture file.

In the previous command, I used `tcpdump` to stream all network traffic. Here, I'll use a filter and other `tcpdump` configuration options to save a small sample that contains only web (TCP port 80) network packet data.

1. Capture packet data into a file called `capture.pcap`:
    ```sh
    sudo tcpdump -i eth0 -nn -c9 port 80 -w capture.pcap &
    ```

   ![T3 1](https://github.com/user-attachments/assets/652c9087-7019-49fa-8230-4bae9e286aea)

    I must press the **ENTER** key to get my command prompt back after running this command. My initial attempt resulted in a syntax error because I missed a space between "port" and "80."

    This command will run `tcpdump` in the background with the following options:
    * `-i eth0`: Capture data from the `eth0` interface.
    * `-nn`: Do not attempt to resolve IP addresses or ports to names. This is best practice from a security perspective, as the lookup data may not be valid. It also prevents malicious actors from being alerted to an investigation.
    * `-c9`: Capture 9 packets of data and then exit.
    * `port 80`: Filter only port 80 traffic. This is the default HTTP port.
    * `-w capture.pcap`: Save the captured data to the named file.
    * `&`: This is an instruction to the Bash shell to run the command in the background.
  
2. Use `curl` to generate some HTTP (port 80) traffic:
    ```sh
    curl opensource.google.com
    ```

    When the `curl` command is used like this to open a website, it generates some HTTP (TCP port 80) traffic that can be captured.

3. Verify that packet data has been captured:
    ```sh
    ls -l capture.pcap
    ```

   ![T3 2](https://github.com/user-attachments/assets/83f7cb95-8eed-40f5-9984-6ce97319fc4e)

## Task 4: Filter the Captured Packet Data

In this task, I'll use `tcpdump` to filter data from the packet capture file I saved previously.

1. Use the `tcpdump` command to filter the packet header data from the `capture.pcap` capture file:
    ```sh
    sudo tcpdump -nn -r capture.pcap -v
    ```

    This command will run `tcpdump` with the following options:
    * `-nn`: Disable port and protocol name lookup.
    * `-r`: Read capture data from the named file.
    * `-v`: Display detailed packet data.

    I must specify the `-nn` switch again here, as I want to make sure `tcpdump` does not perform name lookups of either IP addresses or ports, since this can alert threat actors.

    This returns output data similar to the following:

    ![T4 1](https://github.com/user-attachments/assets/8a06608e-d60e-4ddf-ba48-1057ab2366c8)

    As in the previous example, I can see the IP packet information along with information about the data that the packet contains.

2. Use the `tcpdump` command to filter the extended packet data from the `capture.pcap` capture file:
    ```sh
    sudo tcpdump -nn -r capture.pcap -X
    ```

    This command will run `tcpdump` with the following options:
    * `-nn`: Disable port and protocol name lookup.
    * `-r`: Read capture data from the named file.
    * `-X`: Display the hexadecimal and ASCII output format packet data. Security analysts can analyze hexadecimal and ASCII output to detect patterns or anomalies during malware analysis or forensic analysis.

**Conclusion**

By completing these tasks, I've demonstrated practical experience in:

* identifying network interfaces,
* using the `tcpdump` command to capture network data for inspection,
* interpreting the information that `tcpdump` outputs regarding a packet, and
* saving and loading packet data for later analysis.


