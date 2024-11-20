# The Data acQuisition Development Kit

DQDK is a framework to develop data acquisition systems over UDP. DQDK uses AF_XDP with an ultra-lightweight UDP/IP stack.
DQDK exploits COTS hardware architectures and advanced OS features to achieve high-performance zero-loss DAQ.

## Build

For Ubuntu
```bash
apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) m4 libnuma-dev libdpdk-dev liburing-dev
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

## TRISTAN Results

| Packet Size | RSS UDP Ports | 1 Frame every | Queues | Wake up Flag | Huge Pages | Batch Size | Interrupts & Cores | Zero loss | Histo | MPPS | Payload Throughput | 
| ----------- | ------ | --------- | ------------- | ----------- | ------ | --------- | ------------- | ----------- | ------ | ---- | ---- |
| 3392 | 2 | 295nsec | 2 | Yes | Yes | 2048 | 2 Cores / Queue (ints and app) | Yes | No | 3.45 | 93.6% |

## Usage

[TODO]
