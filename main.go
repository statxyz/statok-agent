package main

import (
	"github.com/godknowsiamgood/gostatok"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func startCPUCollect() {
	const cpuUsageMetricName = "host_cpu_usage"

	var prevTimes cpu.TimesStat

	initialTimes, err := cpu.Times(false)
	if err != nil {
		return
	}
	if len(initialTimes) > 0 {
		prevTimes = initialTimes[0]
	}

	for {
		time.Sleep(5 * time.Second)

		currentTimes, err := cpu.Times(false)
		if err != nil {
			return
		}

		if len(currentTimes) > 0 {
			curr := currentTimes[0]
			prev := prevTimes

			userDiff := curr.User - prev.User
			systemDiff := curr.System - prev.System
			idleDiff := curr.Idle - prev.Idle
			totalDiff := userDiff + systemDiff + idleDiff

			userPct := (userDiff / totalDiff) * 100
			systemPct := (systemDiff / totalDiff) * 100
			idlePct := (idleDiff / totalDiff) * 100

			gostatok.EventValue(cpuUsageMetricName, userPct, "user")
			gostatok.EventValue(cpuUsageMetricName, systemPct, "system")
			gostatok.EventValue(cpuUsageMetricName, idlePct, "idle")

			prevTimes = curr
		}
	}
}

func byteToMb(bytes uint64) uint64 {
	return bytes / 1024 / 1024
}

func startMemoryCollect() {
	const memoryMetricName = "host_memory"

	for {
		time.Sleep(time.Second * 5)
		v, err := mem.VirtualMemory()
		if err != nil {
			continue
		}

		gostatok.EventValue(memoryMetricName, float64(byteToMb(v.Total)), "total")
		gostatok.EventValue(memoryMetricName, float64(byteToMb(v.Available)), "available")
		gostatok.EventValue(memoryMetricName, float64(byteToMb(v.Used)), "used")
		gostatok.EventValue(memoryMetricName, float64(byteToMb(v.Free)), "free")
	}
}

func startDiskCollect() {
	const diskMetricName = "host_disk"

	for {
		time.Sleep(time.Second * 10)

		partitions, err := disk.Partitions(false)
		if err != nil {
			continue
		}

		for _, partition := range partitions {
			usage, err := disk.Usage(partition.Mountpoint)
			if err != nil {
				continue
			}

			diskName := partition.Device

			gostatok.EventValue(diskMetricName, float64(byteToMb(usage.Total)), "total", diskName)
			gostatok.EventValue(diskMetricName, float64(byteToMb(usage.Used)), "used", diskName)
			gostatok.EventValue(diskMetricName, float64(byteToMb(usage.Free)), "available", diskName)
		}
	}
}

func collectDiskIO() {
	const diskIOThroughputMetricName = "host_disk_io_throughput"
	const diskIOReadsWritesMetricName = "host_disk_io_reads_writes"

	var prevIOCounters map[string]disk.IOCountersStat
	var mu sync.Mutex

	for {
		time.Sleep(time.Second * 3)

		currentIOCounters, err := disk.IOCounters()
		if err != nil {
			continue
		}

		mu.Lock()
		if prevIOCounters != nil {
			for device, currentCounter := range currentIOCounters {
				if prevCounter, exists := prevIOCounters[device]; exists {
					readBytesDiff := currentCounter.ReadBytes - prevCounter.ReadBytes
					writeBytesDiff := currentCounter.WriteBytes - prevCounter.WriteBytes
					readCountDiff := currentCounter.ReadCount - prevCounter.ReadCount
					writeCountDiff := currentCounter.WriteCount - prevCounter.WriteCount

					if readBytesDiff == 0 && writeBytesDiff == 0 && readCountDiff == 0 && writeCountDiff == 0 {
						continue
					}

					gostatok.Event(diskIOThroughputMetricName, int(byteToMb(readBytesDiff)), device, "read")
					gostatok.Event(diskIOThroughputMetricName, int(byteToMb(writeBytesDiff)), device, "write")
					gostatok.Event(diskIOReadsWritesMetricName, int(readCountDiff), device, "read")
					gostatok.Event(diskIOReadsWritesMetricName, int(writeCountDiff), device, "write")
				}
			}
		}
		prevIOCounters = currentIOCounters
		mu.Unlock()
	}
}

func collectNetwork() {
	const networkThroughputMetricName = "host_network_throughput"
	const networkPacketsMetricName = "host_network_packets"

	var prevNetIOCounters map[string]net.IOCountersStat
	var mu sync.Mutex

	for {
		time.Sleep(time.Second * 3)

		currentNetIOCounters, err := net.IOCounters(true)
		if err != nil {
			continue
		}

		mu.Lock()
		if prevNetIOCounters != nil {
			for _, currentCounter := range currentNetIOCounters {
				if prevCounter, exists := prevNetIOCounters[currentCounter.Name]; exists {
					bytesSentDiff := currentCounter.BytesSent - prevCounter.BytesSent
					bytesRecvDiff := currentCounter.BytesRecv - prevCounter.BytesRecv
					packetsSentDiff := currentCounter.PacketsSent - prevCounter.PacketsSent
					packetsRecvDiff := currentCounter.PacketsRecv - prevCounter.PacketsRecv

					if bytesSentDiff == 0 && bytesRecvDiff == 0 && packetsSentDiff == 0 && packetsRecvDiff == 0 {
						continue
					}

					gostatok.Event(networkThroughputMetricName, int(bytesSentDiff), currentCounter.Name, "tx")
					gostatok.Event(networkThroughputMetricName, int(bytesRecvDiff), currentCounter.Name, "rx")
					gostatok.Event(networkPacketsMetricName, int(packetsSentDiff), currentCounter.Name, "tx")
					gostatok.Event(networkPacketsMetricName, int(packetsRecvDiff), currentCounter.Name, "rx")
				}
			}
		}
		prevNetIOCounters = make(map[string]net.IOCountersStat)
		for _, counter := range currentNetIOCounters {
			prevNetIOCounters[counter.Name] = counter
		}
		mu.Unlock()
	}
}

type CustomRoundTripper struct {
	Proxied http.RoundTripper
}

func (c *CustomRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = "localhost:8085"
	req.URL.Scheme = "http"
	return c.Proxied.RoundTrip(req)
}

func main() {
	gostatok.Init(gostatok.Options{
		APIKey: "Test",
		//HTTPClient: &http.Client{
		//	Transport: &CustomRoundTripper{
		//		Proxied: http.DefaultTransport,
		//	}},
	})

	go startCPUCollect()
	go startMemoryCollect()
	go startDiskCollect()
	go collectDiskIO()
	go collectNetwork()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	<-sigs
}
