// iLO scanner
// Attempt to reach '/xmldata?item=ALL' page and parse the result.
// (c) Airbus Group, Airbus Group Innovations

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// List of targets in CIDR format
// can be commented and used args instead in the main func
var (
	targets = []string{
		"10.0.0.0/8"}
)

// All result are store in /tmp/iloscan.log , not necessary the best location :p
var path = "/tmp/iloscan.log"

// A WaitGroup waits for a collection of goroutines to finish. The main loop calls Add(1)
// to set the number of goroutines to wait for. Then each of the goroutines runs and calls Done
// when finished.
var wg sync.WaitGroup

// A channel that acts as a counting semaphore. Only allow X concurrent connections.
// The number here can be adjusted up or down. If too many open files/sockets then
// adjust this down. Lower numbers mean slower scan times.
// `ls /proc/pidof netscan/fd | wc -l` should be just under this
var sem = make(chan struct{}, 254)

// ILO struct which contains the complete
// array of all iinformations
type rimp struct {
	XMLName xml.Name `xml:"RIMP"`
	RIMP    []HSI    `xml:"HSI"`
	RIMP1   []MP     `xml:"MP"`
	//	rimp    []spatial `xml:"SPATIAL"`
	//	rimp    []health  `xml:"HEALTH"`
}

// the HSI struct, which contains product info
type HSI struct {
	XMLName xml.Name `xml:"HSI"`
	SPN     string   `xml:"SPN"`
}

// the MP struct, which contains version
type MP struct {
	XMLName xml.Name `xml:"MP"`
	FWRI    string   `xml:"FWRI"`
	SN      string   `xml:"SN"`
	UUID    string   `xml:"UUID"`
}

// Structure for http response
type ContentResponse struct {
	url      string
	response *http.Response
	data     []byte
	err      error
}

// Channel for all urls from targets
var urls = make(chan string, 512)

// CIDR to IP address list
func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Get XML on iLO interface
func getContent(url string) {

	// bypass SSL handcheck
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(5 * time.Second)
	client := &http.Client{Transport: tr, Timeout: timeout}
	fmt.Printf("Fetching %s \n", url)
	resp, err := client.Get("https://" + url + "/xmldata?item=ALL")

	if err != nil {
		fmt.Printf("No iLO on %s \n", url)
		//		fmt.Printf("Problem getting the response: %s\n\n", err)
		//if resp != nil && resp.StatusCode == http.StatusOK {
		//	fmt.Printf("Getting a response: \n")
	} else {
		defer resp.Body.Close() // don't leak resources
		data, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			fmt.Sprintf("while reading %s: %v", url, err)
		}

		fmt.Printf("%s status: %s\n", url, resp.Status)
		if resp.StatusCode == http.StatusOK {
			var info rimp
			xml.Unmarshal(data, &info)
			fmt.Println(info)

			// open file using READ & WRITE permission
			f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			w := bufio.NewWriter(f)
			w.WriteString(url)
			fmt.Fprintln(w, info)
			w.Flush()
			f.Close()

			resp.Body.Close()
		}
	}
}

func GenerateUrlsFromTargets(targets []string) {
	for _, target := range targets {
		ip, ipnet, _ := net.ParseCIDR(target)
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			urls <- ip.String()
			fmt.Println("Generated", ip.String())
		}
	}
	close(urls)
}

func main() {

	targets := []string{os.Args[1]}

	// Remember your path location
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			fmt.Printf("file %s has not been created", path)
		}
		defer file.Close()
	}
	generate := func(t []string) {
		wg.Add(1)
		defer wg.Done()
		GenerateUrlsFromTargets(t)
	}
	go generate(targets)

	f := func(u string) {
		wg.Add(1)
		defer wg.Done()
		getContent(u)
		<-sem
	}

	for url := range urls {
		sem <- struct{}{}
		go f(url)
	}
	wg.Wait()
	close(sem)

	fmt.Printf("Done")

}
