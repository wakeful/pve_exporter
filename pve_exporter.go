package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

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
	UpTime    float64 `json:"uptime"`
	CpuTotal  float64 `json:"maxcpu"`
	RamTotal  float64 `json:"maxmem"`
	RamFree   float64 `json:"mem"`
	DiskTotal float64 `json:"maxdisk"`
	DiskFree  float64 `json:"disk"`
}

type nodeResponse struct {
	Data []node `json:"data"`
}

type lxc struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	UpTime    float64 `json:"uptime"`
	CpuCount  float64 `json:"cpus"`
	DiskTotal float64 `json:"maxdisk"`
	DiskFree  float64 `json:"disk"`
	DiskRead  float64 `json:"diskread"`
	DiskWrite float64 `json:"diskwrite"`
	RamTotal  float64 `json:"maxmem"`
	RamFree   float64 `json:"mem"`
	SwapTotal float64 `json:"maxswap"`
	SwapFree  float64 `json:"swap"`
	NetIn     float64 `json:"netin"`
	NetOut    float64 `json:"netout"`
}

type lxcResponse struct {
	Data []lxc `json:"data"`
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

func (c *Client) GetNodes() (data []node, err error) {

	var nodeData nodeResponse

	request, err := http.NewRequest("GET", c.url+"nodes", bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}

	resp, err := c.call(request)
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

	request, err := http.NewRequest("GET", c.url+"nodes/"+nodeID+"/lxc", bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}

	resp, err := c.call(request)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(resp, &lxcData); err != nil {
		return nil, err
	}

	return lxcData.Data, nil
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
		log.Fatal(err)
	}

	e.up.Set(1)
	ch <- e.up

	nodeList, err := e.pve.GetNodes()
	if err != nil {
		log.Fatalln(err)
	} else {
		for _, node := range nodeList {
			ch <- prometheus.MustNewConstMetric(
				clusterNodeUpTime, prometheus.GaugeValue, node.UpTime, node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeCpuTotal, prometheus.GaugeValue, node.CpuTotal, node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeRamTotal, prometheus.GaugeValue, node.RamTotal, node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeRamFree, prometheus.GaugeValue, node.RamFree, node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeDiskTotal, prometheus.GaugeValue, node.DiskTotal, node.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				clusterNodeDiskFree, prometheus.GaugeValue, node.DiskFree, node.Name,
			)

			lxcList, err := e.pve.GetLxc(node.Name)
			if err != nil {
				log.Fatalln(err)
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
						clusterLxcUpTime, prometheus.GaugeValue, lxc.UpTime, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcCpuCount, prometheus.GaugeValue, lxc.CpuCount, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskTotal, prometheus.GaugeValue, lxc.DiskTotal, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskFree, prometheus.GaugeValue, lxc.DiskFree, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskRead, prometheus.GaugeValue, lxc.DiskRead, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcDiskWrite, prometheus.GaugeValue, lxc.DiskWrite, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcRamTotal, prometheus.GaugeValue, lxc.RamTotal, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcRamFree, prometheus.GaugeValue, lxc.RamFree, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcSwapTotal, prometheus.GaugeValue, lxc.SwapTotal, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcSwapFree, prometheus.GaugeValue, lxc.SwapFree, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcNetIn, prometheus.GaugeValue, lxc.NetIn, node.Name, lxc.Name,
					)
					ch <- prometheus.MustNewConstMetric(
						clusterLxcNetOut, prometheus.GaugeValue, lxc.NetOut, node.Name, lxc.Name,
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
	prometheus.Unregister(prometheus.NewProcessCollector(os.Getegid(), ""))
	prometheus.MustRegister(NewExporter())

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, *metricsPath, http.StatusMovedPermanently)
	})

	log.Fatal(http.ListenAndServe(*listenAddress, nil))

}
