# The Data acQuisition Development Kit

DQDK is a framework to develop data acquisition systems over UDP. DQDK uses AF_XDP with an ultra-lightweight UDP/IP stack.
DQDK exploits COTS hardware architectures and advanced OS features to achieve high-performance zero-loss DAQ.

### Citation

Cite our paper:

> J. Mostafa, D. Tcherniakhovski, S. Chilingaryan, M. Balzer, A. Kopmann and J. Becker, **"100 Gbit/s UDP Data Acquisition on Linux Using AF_XDP: The TRISTAN Detector"** in IEEE Transactions on Nuclear Science, [doi: 10.1109/TNS.2024.3452469](https://ieeexplore.ieee.org/document/10659873).



```bibtex
@ARTICLE{10659873,
  author={Mostafa, Jalal and Tcherniakhovski, Denis and Chilingaryan, Suren and Balzer, Matthias and Kopmann, Andreas and Becker, J\"urgen},
  journal={IEEE Transactions on Nuclear Science},
  title={100 Gbit/s UDP Data Acquisition on Linux Using AF_XDP: The TRISTAN Detector},
  year={2024},
  volume={},
  number={},
  pages={1-1},
  doi={10.1109/TNS.2024.3452469}}
```

## Build and Install

**Requires** Linux Kernel 6.6+
Tested on Ubuntu 24.04.01 (Kernel 6.8)

For Ubuntu
```bash
apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) m4 libnuma-dev liburing-dev
```

```bash
git clone --recursive https://github.com/kit-ipe/dqdk.git
cd dqdk
pushd xdp-tools/xdp-loader; make; sudo make install; popd
cd src
make
sudo make install
```

To uninstall run `sudo make uninstall` in `src`

## Latency Tests
DQDK uses NIC RX HW Timestamping to timestamp the packet on arrival.
Another timestamp is issued inside DQDK user-space code. The latency is calculated by calculating the differnece between the 2 timestamps.
The NIC clock (PHC) and the system clock should be synchronized.
An PTP service can be used to do this synchronization. Example:
```bash
ptp -i eth0 -m
phc2sys -s eth0 -c CLOCK_REALTIME -O 0
```
Run DQDK in debug mode to measure latencies. Make sure all NIC offloading capabilities are enabled and working properly, otherwise a kernel panic occurs and the server needs restarting. Disable ntpd, chronyd, systemd-timesyncd and systemd-timedated services because they will conflict with ptp4l.

## TRISTAN Results

| Packet Size | RSS UDP Ports | 1 Frame every | Queues | Wake up Flag | Huge Pages | Batch Size | Interrupts & Cores | Zero loss | Histo | MPPS | Payload Throughput | 
| ----------- | ------ | --------- | ------------- | ----------- | ------ | --------- | ------------- | ----------- | ------ | ---- | ---- |
| 3392 | 2 | 295nsec | 2 | Yes | Yes | 2048 | 2 Cores / Queue (ints and app) | Yes | No | 3.45 | 93.6% |

## Usage

[TODO]
