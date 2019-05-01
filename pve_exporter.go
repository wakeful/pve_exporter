package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/namsral/flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

type authResponse struct {
	Data struct {
		Ticket string `json:"ticket"`
		Token  string `json:"Token"`
	} `json:"data"`
}

type Client struct {
	client                         *http.Client
	authTicket, authToken          string
	password, realm, url, username string
}

type node struct {
	Id        string  `json:"id"`
	Name      string  `json:"node"`
	UpTime    json.Number `json:"uptime"`
	CpuTotal  json.Number `json:"maxcpu"`
	CpuUsage  json.Number `json:"cpu"`
	RamTotal  json.Number `json:"maxmem"`
	RamFree   json.Number `json:"mem"`
	DiskTotal json.Number `json:"maxdisk"`
	DiskFree  json.Number `json:"disk"`
}

type nodeResponse struct {
	Data []node `json:"data"`
}

type lxc struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	UpTime    json.Number `json:"uptime"`
	CpuCount  json.Number `json:"cpus"`
	CpuUsage  json.Number `json:"cpu"`
	DiskTotal json.Number  `json:"maxdisk"`
	DiskFree  json.Number  `json:"disk"`
	DiskRead  json.Number `json:"diskread"`
	DiskWrite json.Number `json:"diskwrite"`
	RamTotal  json.Number `json:"maxmem"`
	RamFree   json.Number `json:"mem"`
	SwapTotal json.Number `json:"maxswap"`
	SwapFree  json.Number `json:"swap"`
	NetIn     json.Number `json:"netin"`
	NetOut    json.Number `json:"netout"`
}

type lxcResponse struct {
	Data []lxc `json:"data"`
}

type qemu struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	UpTime    json.Number `json:"uptime"`
	CpuCount  json.Number `json:"cpus"`
	CpuUsage  json.Number `json:"cpu"`
	DiskTotal json.Number `json:"maxdisk"`
	DiskFree  json.Number `json:"disk"`
	DiskRead  json.Number `json:"diskread"`
	DiskWrite json.Number `json:"diskwrite"`
	RamTotal  json.Number `json:"maxmem"`
	RamFree   json.Number `json:"mem"`
	NetIn     json.Number `json:"netin"`
	NetOut    json.Number `json:"netout"`
}

type qemuResponse struct {
	Data []qemu `json:"data"`
}

func mu(a ...interface{}) []interface{} {
    return a
}

func jNumberToFloat(number json.Number) float64 {
	return mu(number.Float64())[0].(float64)
}

func NewClient(url, username, password, realm string, timeout int, verifySSL bool) *Client {

	if realm == "" {
		realm = "pam"
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL},
	}

	return &Client{
		client: &http.Client{
			Transport: tr,
			Timeout:   time.Duration(timeout) * time.Second,
		},
		username: username,
		password: password,
		realm:    realm,
		url:      url + "/api2/json/",
	}
}

func (c *Client) call(request *http.Request) (message []byte, err error) {

	if c.authTicket != "" {
		request.Header.Set("Cookie", "PVEAuthCookie="+c.authTicket)
		request.Header.Set("Token", c.authToken)
	}

	response, err := c.client.Do(request)

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()
	message, err = ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}

	return message, nil
}

func (c *Client) Auth() (err error) {
	payload := "username=" + c.username + "@" + c.realm + "&password=" + c.password
	request, err := http.NewRequest("POST", c.url+"access/ticket", bytes.NewBufferString(payload))

	if err != nil {
		return
	}

	resp, err := c.call(request)

	if err != nil {
		return
	}

	var auth authResponse
	if err = json.Unmarshal(resp, &auth); err != nil {
		return
	}

	c.authTicket = auth.Data.Ticket
	c.authToken = auth.Data.Token

	return nil
}

func (c *Client) Do(endpoint string) ([]byte, error) {

	request, err := http.NewRequest("GET", c.url+endpoint, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}

	resp, err := c.call(request)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) GetNodes() (data []node, err error) {

	var nodeData nodeResponse

	resp, err := c.Do("nodes")
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(resp, &nodeData); err != nil {
		return nil, err
	}

	return nodeData.Data, nil
}

func (c *Client) GetLxc(nodeID string) (data []lxc, err error) {

	var lxcData lxcResponse

	resp, err := c.Do("nodes/" + nodeID + "/lxc")
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(resp, &lxcData); err != nil {
		return nil, err
	}

	return lxcData.Data, nil
}

func (c *Client) GetQemu(nodeID string) (data []qemu, err error) {

	var qemuData qemuResponse

	resp, err := c.Do("nodes/" + nodeID + "/qemu")
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(resp, &qemuData); err != nil {
		return nil, err
	}

	return qemuData.Data, nil
}

const nameSpace = "pve"

var (
	version    = "dev"
	versionUrl = "https://github.com/wakeful/pve_exporter"

	showVersion   = flag.Bool("version", false, "show version and exit")
	listenAddress = flag.String("listen-address", ":9090", "Address on which to expose metrics.")
	metricsPath   = flag.String("telemetry-path", "/metrics", "Path under which to expose metrics.")
	pveUrl        = flag.String("pve-url", "https://127.0.0.1:8006", "URL to your PVE control panel")
	timeout       = flag.Int("timeout", 5, "set request timeout to n (seconds)")
	pveUser       = flag.String("user", "root", "User name used for accessing PVE API")
	pvePassword   = flag.String("password", "1234", "Password for accessing PVE API")
	pveRealm      = flag.String("realm", "pam", "PAM / LDAP auth method")

	clusterNodeUpTime = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "nodes", "up_time"),
		"UpTime for each node in seconds",
		[]string{"node"}, nil,
	)
	clusterNodeCpuTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "nodes", "cpu_total"),
		"Total CPU count on each node",
		[]string{"node"}, nil,
	)
	clusterNodeCpuUsage = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "nodes", "cpu_usage"),
		"CPU usage on each node",
		[]string{"node"}, nil,
	)
	clusterNodeRamTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "nodes", "ram_total"),
		"Total RAM on each node",
		[]string{"node"}, nil,
	)
	clusterNodeRamFree = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "nodes", "ram_free"),
		"Free RAM on each node",
		[]string{"node"}, nil,
	)
	clusterNodeDiskTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "nodes", "disk_total"),
		"Disk size on each node",
		[]string{"node"}, nil,
	)
	clusterNodeDiskFree = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "nodes", "disk_free"),
		"Free disk space on each node",
		[]string{"node"}, nil,
	)
	clusterLxcUp = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "up"),
		"is the LXC running",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcUpTime = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "up_time"),
		"UpTime for each LXC ",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcCpuCount = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "cpu_count"),
		"Total CPU count for each LXC",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcCpuUsage = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "cpu_usage"),
		"CPU usage for each LXC",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcDiskTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "disk_total"),
		"Disk size for each LXC",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcDiskFree = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "disk_free"),
		"Free disk space for each LXC",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcDiskRead = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "disk_read"),
		"LXC disk read",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcDiskWrite = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "disk_write"),
		"LXC disk write",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcRamTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "ram_total"),
		"LXC RAM total",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcRamFree = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "ram_free"),
		"LXC Free RAM",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcSwapTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "swap_total"),
		"LXC SWAP Total",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcSwapFree = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "swap_free"),
		"LXC Free SWAP",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcNetIn = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "net_in"),
		"LXC Network In",
		[]string{"node", "lxc"}, nil,
	)
	clusterLxcNetOut = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "lxc", "net_out"),
		"LXC Network Out",
		[]string{"node", "lxc"}, nil,
	)
	clusterQemuUp = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "up"),
		"is the QEMU VM running",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuUpTime = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "up_time"),
		"UpTime for each QEMU VM ",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuCpuCount = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "cpu_count"),
		"Total CPU count for each QEMU VM",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuCpuUsage = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "cpu_usage"),
		"CPU usage for each QEMU VM",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuDiskTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "disk_total"),
		"Disk size for each QEMU VM",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuDiskFree = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "disk_free"),
		"Free disk space for each QEMU VM",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuDiskRead = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "disk_read"),
		"QEMU VM disk read",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuDiskWrite = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "disk_write"),
		"QEMU VM disk write",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuRamTotal = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "ram_total"),
		"QEMU VM RAM total",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuRamFree = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "ram_free"),
		"QEMU VM Free RAM",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuNetIn = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "net_in"),
		"QEMU VM Network In",
		[]string{"node", "qemu"}, nil,
	)
	clusterQemuNetOut = prometheus.NewDesc(
		prometheus.BuildFQName(nameSpace, "qemu", "net_out"),
		"QEMU VM Network Out",
		[]string{"node", "qemu"}, nil,
	)
)

type Exporter struct {
	pve *Client
	up  prometheus.Gauge
}

func (e Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.up.Describe(ch)

	ch <- clusterNodeUpTime
}

func (e Exporter) Collect(ch chan<- prometheus.Metric) {

	if err := e.pve.Auth(); err != nil {
		e.up.Set(0)
		ch <- e.up

		log.Errorln(err)
		return
	}

	e.up.Set(1)
	ch <- e.up

	nodeList, err := e.pve.GetNodes()
	if err != nil {
		log.Errorln(err)
	} else {
		for _, node := range nodeList {
			ch <- prometheus.MustNewConstMetric(
				clusterNodeUpTime, prometheus.GaugeValue, jNumberToFloat(node.UpTime), node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeCpuTotal, prometheus.GaugeValue, jNumberToFloat(node.CpuTotal), node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeCpuUsage, prometheus.GaugeValue, jNumberToFloat(node.CpuUsage), node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeRamTotal, prometheus.GaugeValue, jNumberToFloat(node.RamTotal), node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeRamFree, prometheus.GaugeValue, jNumberToFloat(node.RamFree), node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeDiskTotal, prometheus.GaugeValue, jNumberToFloat(node.DiskTotal), node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeDiskFree, prometheus.GaugeValue, jNumberToFloat(node.DiskFree), node.Name,
			)

			qemuList, err := e.pve.GetQemu(node.Name)
			if err != nil {
				log.Errorln(err)
			} else {
				for _, qVM := range qemuList {

					var qVMup float64 = 0
					if strings.ToLower(qVM.Status) == "running" {
						qVMup = 1
					}

					ch <- prometheus.MustNewConstMetric(
						clusterQemuUp, prometheus.GaugeValue, qVMup, node.Name, qVM.Name,
					)

					ch <- prometheus.MustNewConstMetric(
						clusterQemuUpTime, prometheus.GaugeValue, jNumberToFloat(qVM.UpTime), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuCpuCount, prometheus.GaugeValue, jNumberToFloat(qVM.CpuCount), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuCpuUsage, prometheus.GaugeValue, jNumberToFloat(qVM.CpuUsage), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuDiskTotal, prometheus.GaugeValue, jNumberToFloat(qVM.DiskTotal), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuDiskFree, prometheus.GaugeValue, jNumberToFloat(qVM.DiskFree), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuDiskRead, prometheus.GaugeValue, jNumberToFloat(qVM.DiskRead), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuDiskWrite, prometheus.GaugeValue, jNumberToFloat(qVM.DiskWrite), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuRamTotal, prometheus.GaugeValue, jNumberToFloat(qVM.RamTotal), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuRamFree, prometheus.GaugeValue, jNumberToFloat(qVM.RamFree), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuNetIn, prometheus.GaugeValue, jNumberToFloat(qVM.NetIn), node.Name, qVM.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterQemuNetOut, prometheus.GaugeValue, jNumberToFloat(qVM.NetOut), node.Name, qVM.Name,
					)
				}
			}

			lxcList, err := e.pve.GetLxc(node.Name)
			if err != nil {
				log.Errorln(err)
			} else {
				for _, lxc := range lxcList {

					var lxcUp float64 = 0
					if strings.ToLower(lxc.Status) == "running" {
						lxcUp = 1
					}

					ch <- prometheus.MustNewConstMetric(
						clusterLxcUp, prometheus.GaugeValue, lxcUp, node.Name, lxc.Name,
					)

					ch <- prometheus.MustNewConstMetric(
						clusterLxcUpTime, prometheus.GaugeValue, jNumberToFloat(lxc.UpTime), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcCpuCount, prometheus.GaugeValue, jNumberToFloat(lxc.CpuCount), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcCpuUsage, prometheus.GaugeValue, jNumberToFloat(lxc.CpuUsage), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskTotal, prometheus.GaugeValue, jNumberToFloat(lxc.DiskTotal), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskFree, prometheus.GaugeValue, jNumberToFloat(lxc.DiskFree), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskRead, prometheus.GaugeValue, jNumberToFloat(lxc.DiskRead), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskWrite, prometheus.GaugeValue, jNumberToFloat(lxc.DiskWrite), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcRamTotal, prometheus.GaugeValue, jNumberToFloat(lxc.RamTotal), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcRamFree, prometheus.GaugeValue, jNumberToFloat(lxc.RamFree), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcSwapTotal, prometheus.GaugeValue, jNumberToFloat(lxc.SwapTotal), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcSwapFree, prometheus.GaugeValue, jNumberToFloat(lxc.SwapFree), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcNetIn, prometheus.GaugeValue, jNumberToFloat(lxc.NetIn), node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcNetOut, prometheus.GaugeValue, jNumberToFloat(lxc.NetOut), node.Name, lxc.Name,
					)
				}
			}

		}
	}

}

func NewExporter() *Exporter {

	return &Exporter{
		pve: NewClient(*pveUrl, *pveUser, *pvePassword, *pveRealm, *timeout, false),
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: nameSpace,
			Name:      "up",
			Help:      "was the last scrape of PVE successful.",
		}),
	}

}

func main() {

	flag.Parse()

	if *showVersion {
		fmt.Printf("pve_exporter\n url: %s\n version: %s\n", versionUrl, version)
		os.Exit(2)
	}

	log.Infoln("Starting pve_exporter")

	prometheus.Unregister(prometheus.NewGoCollector())
	prometheus.Unregister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	prometheus.MustRegister(NewExporter())

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, *metricsPath, http.StatusMovedPermanently)
	})

	log.Fatal(http.ListenAndServe(*listenAddress, nil))

}
