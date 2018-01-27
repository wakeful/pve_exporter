# Proxmox VE exporter

A [Prometheus](https://prometheus.io/) exporter that collects [Proxmox VE](https://www.proxmox.com/en/) metrics.

### Usage

```sh
$ ./pve_exporter -h
Usage of ./pve_exporter:
  -listen-address string
        Address on which to expose metrics. (default ":9090")
  -password string
        Password for accessing PVE API (default "1234")
  -pve-url string
        URL to your PVE control panel (default "https://127.0.0.1:8006")
  -realm string
        PAM / LDAP auth method (default "pam")
  -telemetry-path string
        Path under which to expose metrics. (default "/metrics")
  -timeout int
        set request timeout to n (seconds) (default 5)
  -user string
        User name used for accessing PVE API (default "root")
  -version
        show version and exit
```

## Metrics

```
# HELP pve_lxc_cpu_count Total CPU count for each LXC
# TYPE pve_lxc_cpu_count gauge
pve_lxc_cpu_count{lxc="testo01",node="pve1"} 1
pve_lxc_cpu_count{lxc="testo02",node="pve1"} 1
# HELP pve_lxc_disk_free Free disk space for each LXC
# TYPE pve_lxc_disk_free gauge
pve_lxc_disk_free{lxc="testo01",node="pve1"} 1.7719296e+07
pve_lxc_disk_free{lxc="testo02",node="pve1"} 1.4569472e+07
# HELP pve_lxc_disk_read LXC disk read
# TYPE pve_lxc_disk_read gauge
pve_lxc_disk_read{lxc="testo01",node="pve1"} 8.855552e+06
pve_lxc_disk_read{lxc="testo02",node="pve1"} 8.802304e+06
# HELP pve_lxc_disk_total Disk size for each LXC
# TYPE pve_lxc_disk_total gauge
pve_lxc_disk_total{lxc="testo01",node="pve1"} 3.1035392e+09
pve_lxc_disk_total{lxc="testo02",node="pve1"} 2.046640128e+09
# HELP pve_lxc_disk_write LXC disk write
# TYPE pve_lxc_disk_write gauge
pve_lxc_disk_write{lxc="testo01",node="pve1"} 16384
pve_lxc_disk_write{lxc="testo02",node="pve1"} 32768
# HELP pve_lxc_net_in LXC Network In
# TYPE pve_lxc_net_in gauge
pve_lxc_net_in{lxc="testo01",node="pve1"} 1257
pve_lxc_net_in{lxc="testo02",node="pve1"} 45020
# HELP pve_lxc_net_out LXC Network Out
# TYPE pve_lxc_net_out gauge
pve_lxc_net_out{lxc="testo01",node="pve1"} 3600
pve_lxc_net_out{lxc="testo02",node="pve1"} 39985
# HELP pve_lxc_ram_free LXC Free RAM
# TYPE pve_lxc_ram_free gauge
pve_lxc_ram_free{lxc="testo01",node="pve1"} 1.67936e+06
pve_lxc_ram_free{lxc="testo02",node="pve1"} 1.728512e+06
# HELP pve_lxc_ram_total LXC RAM total
# TYPE pve_lxc_ram_total gauge
pve_lxc_ram_total{lxc="testo01",node="pve1"} 1.6777216e+08
pve_lxc_ram_total{lxc="testo02",node="pve1"} 1.34217728e+08
# HELP pve_lxc_swap_free LXC Free SWAP
# TYPE pve_lxc_swap_free gauge
pve_lxc_swap_free{lxc="testo01",node="pve1"} 0
pve_lxc_swap_free{lxc="testo02",node="pve1"} 0
# HELP pve_lxc_swap_total LXC SWAP Total
# TYPE pve_lxc_swap_total gauge
pve_lxc_swap_total{lxc="testo01",node="pve1"} 1.6777216e+08
pve_lxc_swap_total{lxc="testo02",node="pve1"} 1.34217728e+08
# HELP pve_lxc_up is the LXC running
# TYPE pve_lxc_up gauge
pve_lxc_up{lxc="testo01",node="pve1"} 1
pve_lxc_up{lxc="testo02",node="pve1"} 1
# HELP pve_lxc_up_time UpTime for each LXC 
# TYPE pve_lxc_up_time gauge
pve_lxc_up_time{lxc="testo01",node="pve1"} 2992
pve_lxc_up_time{lxc="testo02",node="pve1"} 2913
# HELP pve_nodes_cpu_total Total CPU count on each node
# TYPE pve_nodes_cpu_total gauge
pve_nodes_cpu_total{node="pve1"} 1
# HELP pve_nodes_disk_free Free disk space on each node
# TYPE pve_nodes_disk_free gauge
pve_nodes_disk_free{node="pve1"} 1.397420032e+09
# HELP pve_nodes_disk_total Disk size on each node
# TYPE pve_nodes_disk_total gauge
pve_nodes_disk_total{node="pve1"} 7.066886144e+09
# HELP pve_nodes_ram_free Free RAM on each node
# TYPE pve_nodes_ram_free gauge
pve_nodes_ram_free{node="pve1"} 7.50903296e+08
# HELP pve_nodes_ram_total Total RAM on each node
# TYPE pve_nodes_ram_total gauge
pve_nodes_ram_total{node="pve1"} 2.363011072e+09
# HELP pve_nodes_up_time UpTime for each node in seconds
# TYPE pve_nodes_up_time gauge
pve_nodes_up_time{node="pve1"} 3122
# HELP pve_qemu_cpu_count Total CPU count for each QEMU VM
# TYPE pve_qemu_cpu_count gauge
pve_qemu_cpu_count{node="pve1",qemu="vm12"} 1
# HELP pve_qemu_disk_free Free disk space for each QEMU VM
# TYPE pve_qemu_disk_free gauge
pve_qemu_disk_free{node="pve1",qemu="vm12"} 0
# HELP pve_qemu_disk_read QEMU VM disk read
# TYPE pve_qemu_disk_read gauge
pve_qemu_disk_read{node="pve1",qemu="vm12"} 0
# HELP pve_qemu_disk_total Disk size for each QEMU VM
# TYPE pve_qemu_disk_total gauge
pve_qemu_disk_total{node="pve1",qemu="vm12"} 3.4359738368e+10
# HELP pve_qemu_disk_write QEMU VM disk write
# TYPE pve_qemu_disk_write gauge
pve_qemu_disk_write{node="pve1",qemu="vm12"} 0
# HELP pve_qemu_net_in QEMU VM Network In
# TYPE pve_qemu_net_in gauge
pve_qemu_net_in{node="pve1",qemu="vm12"} 0
# HELP pve_qemu_net_out QEMU VM Network Out
# TYPE pve_qemu_net_out gauge
pve_qemu_net_out{node="pve1",qemu="vm12"} 0
# HELP pve_qemu_ram_free QEMU VM Free RAM
# TYPE pve_qemu_ram_free gauge
pve_qemu_ram_free{node="pve1",qemu="vm12"} 0
# HELP pve_qemu_ram_total QEMU VM RAM total
# TYPE pve_qemu_ram_total gauge
pve_qemu_ram_total{node="pve1",qemu="vm12"} 5.36870912e+08
# HELP pve_qemu_up is the QEMU VM running
# TYPE pve_qemu_up gauge
pve_qemu_up{node="pve1",qemu="vm12"} 0
# HELP pve_qemu_up_time UpTime for each QEMU VM
# TYPE pve_qemu_up_time gauge
pve_qemu_up_time{node="pve1",qemu="vm12"} 0
# HELP pve_up was the last scrape of PVE successful.
# TYPE pve_up gauge
pve_up 1
```
