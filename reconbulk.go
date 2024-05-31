package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Amass       CommandConfig `json:"amass"`
	Subfinder   CommandConfig `json:"subfinder"`
	Assetfinder CommandConfig `json:"assetfinder"`
	Findomain   CommandConfig `json:"findomain"`
	Httpx       CommandConfig `json:"httpx"`
	Naabu       CommandConfig `json:"naabu"`
	Nuclei      CommandConfig `json:"nuclei"`
}

type CommandConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

var config Config

func loadConfig(configPath string) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}
}

func printBanner() {
	fmt.Println(`
	______                    ______       _ _    
	| ___ \                   | ___ \     | | |   
	| |_/ /___  ___ ___  _ __ | |_/ /_   _| | | __
	|    // _ \/ __/ _ \| '_ \| ___ \ | | | | |/ /
	| |\ \  __/ (_| (_) | | | | |_/ / |_| | |   < 
	\_| \_\___|\___\___/|_| |_\____/ \__,_|_|_|\_\ .Kocomon	
                                              
                                              
					V.1.0 
					Taurus Omar
					Refactored v.1.0
					Aikazu`)
	fmt.Println()
}

func banner() {
	printBanner()
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func showOutputInRealTime(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
}

func executeCmd(cmd *exec.Cmd, sleepSeconds int) {
	showOutputInRealTime(cmd)
	time.Sleep(time.Duration(sleepSeconds) * time.Second)
	cmd.Run()
}

func startCmd(commandConfig CommandConfig, domain, resultDir, outputFile, resolversFile string) *exec.Cmd {
	cmdArgs := make([]string, len(commandConfig.Args))
	copy(cmdArgs, commandConfig.Args)
	for i := 0; i < len(cmdArgs); i++ {
		cmdArgs[i] = strings.Replace(cmdArgs[i], "{domain}", domain, -1)
		cmdArgs[i] = strings.Replace(cmdArgs[i], "{dir}", resultDir, -1)
		cmdArgs[i] = strings.Replace(cmdArgs[i], "{output}", outputFile, -1)
		cmdArgs[i] = strings.Replace(cmdArgs[i], "{resolvers}", resolversFile, -1)
	}
	cmd := exec.Command(commandConfig.Command, cmdArgs...)
	showOutputInRealTime(cmd)
	return cmd
}

func startAmass(domain, resolversFile, resultDir string) *exec.Cmd {
	outputFile := filepath.Join(resultDir, fmt.Sprintf("amass_%s.txt", domain))
	return startCmd(config.Amass, domain, resultDir, outputFile, resolversFile)
}

func startSubfinder(domain, resolversFile, resultDir string) *exec.Cmd {
	outputFile := filepath.Join(resultDir, fmt.Sprintf("subfinder_%s.txt", domain))
	return startCmd(config.Subfinder, domain, resultDir, outputFile, resolversFile)
}

func startAssetfinder(domain, resultDir string) *exec.Cmd {
	outputFile := filepath.Join(resultDir, fmt.Sprintf("assetfinder_%s.txt", domain))
	return startCmd(config.Assetfinder, domain, resultDir, outputFile, "")
}

func startFindomain(domain, resolversFile, resultDir string) *exec.Cmd {
	outputFile := filepath.Join(resultDir, fmt.Sprintf("findomain_%s.txt", domain))
	return startCmd(config.Findomain, domain, resultDir, outputFile, resolversFile)
}

func findSubdomains(domain, resolversFile, resultDir string) (*exec.Cmd, *exec.Cmd, *exec.Cmd, *exec.Cmd) {
	amassCmd := startAmass(domain, resolversFile, resultDir)
	subfinderCmd := startSubfinder(domain, resolversFile, resultDir)
	assetfinderCmd := startAssetfinder(domain, resultDir)
	findomainCmd := startFindomain(domain, resolversFile, resultDir)

	go executeCmd(amassCmd, 5)
	go executeCmd(subfinderCmd, 5)
	go executeCmd(assetfinderCmd, 5)
	go executeCmd(findomainCmd, 5)

	return amassCmd, subfinderCmd, assetfinderCmd, findomainCmd
}

func scanCRT(domain, resultDir string) {
	fmt.Println("Scanning crt.sh...")
	crtOutput := filepath.Join(resultDir, fmt.Sprintf("%s.crt.txt", domain))
	crtURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	response, err := exec.Command("curl", "-s", crtURL).Output()
	checkErr(err)

	var data []map[string]interface{}
	json.Unmarshal(response, &data)

	uniqueSubdomains := make(map[string]struct{})

	for _, entry := range data {
		nameValue := entry["name_value"].(string)
		if nameValue != "" {
			nameValue = strings.Replace(nameValue, "*.", "", -1)
			uniqueSubdomains[nameValue] = struct{}{}
		}
	}

	writeUniqueSubdomainsToFile(crtOutput, uniqueSubdomains)
	fmt.Printf("crt.sh results written to: %s\n", crtOutput)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func combineSubdomains(domain, resultDir string) {
	fmt.Println("Combining subdomains...")
	amassOutput := filepath.Join(resultDir, fmt.Sprintf("amass_%s.txt", domain))
	subfinderOutput := filepath.Join(resultDir, fmt.Sprintf("subfinder_%s.txt", domain))
	assetfinderOutput := filepath.Join(resultDir, fmt.Sprintf("assetfinder_%s.txt", domain))
	findomainOutput := filepath.Join(resultDir, fmt.Sprintf("findomain_%s.txt", domain))
	crtOutput := filepath.Join(resultDir, fmt.Sprintf("%s.crt.txt", domain))
	subdomainsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.subdomains.txt", domain))

	subdomainFiles := []string{amassOutput, subfinderOutput, assetfinderOutput, findomainOutput, crtOutput}
	uniqueSubdomains := make(map[string]struct{})

	for _, file := range subdomainFiles {
		if fileExists(file) {
			lines, err := ioutil.ReadFile(file)
			checkErr(err)
			for _, line := range strings.Split(string(lines), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					uniqueSubdomains[line] = struct{}{}
				}
			}
		} else {
			fmt.Printf("File not found: %s\n", file)
		}
	}

	writeUniqueSubdomainsToFile(subdomainsOutput, uniqueSubdomains)
	fmt.Printf("Combined subdomains written to: %s\n", subdomainsOutput)
}

func writeUniqueSubdomainsToFile(filename string, uniqueSubdomains map[string]struct{}) {
	subdomains := make([]string, 0, len(uniqueSubdomains))
	for subdomain := range uniqueSubdomains {
		subdomains = append(subdomains, subdomain)
	}
	sort.Strings(subdomains)

	err := ioutil.WriteFile(filename, []byte(strings.Join(subdomains, "\n")+"\n"), 0644)
	checkErr(err)
}

func findIPs(domain, resolversFile, resultDir string) {
	fmt.Println("Now finding IPs for subdomains...")
	subdomainsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.subdomains.txt", domain))
	ipsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.ips.txt", domain))
	cmd := exec.Command(filepath.Join("tools", "massdns"), "-r", resolversFile, "-t", "A", "-o", "S", "-w", ipsOutput, subdomainsOutput)
	showOutputInRealTime(cmd)
	cmd.Run()
	fmt.Printf("IPs written to: %s\n", ipsOutput)
}

func stripANSI(text string) string {
	ansi := regexp.MustCompile(`\x1B(?:[@-Z\\-_]]|\[[0-?]*[ -/]*[@-~])`)
	return ansi.ReplaceAllString(text, "")
}

func stripBrackets(text string) string {
	return strings.Replace(strings.Replace(text, "[", "", -1), "]", "", -1)
}

func scanHttpx(domain, resultDir string) {
	fmt.Println("Scanning subdomains with httpx...")
	subdomainsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.subdomains.txt", domain))
	httpxOutput := filepath.Join(resultDir, fmt.Sprintf("httpx_%s.txt", domain))
	cmd := exec.Command(filepath.Join("tools", "httpx"), "-l", subdomainsOutput, "-title", "-tech-detect", "-status-code", "-o", httpxOutput)
	showOutputInRealTime(cmd)
	cmd.Run()
	fmt.Printf("Httpx results written to: %s\n", httpxOutput)

	fmt.Println("Sorting httpx results...")
	sortedHttpxOutput := filepath.Join(resultDir, fmt.Sprintf("sorted_httpx_%s.txt", domain))

	linesBytes, err := ioutil.ReadFile(httpxOutput)
	checkErr(err)
	lines := strings.Split(string(linesBytes), "\n")

	strippedLines := make([]string, 0, len(lines))
	for _, line := range lines {
		strippedLines = append(strippedLines, stripANSI(line))
	}

	strippedBracketsLines := make([]string, 0, len(strippedLines))
	for _, line := range strippedLines {
		strippedBracketsLines = append(strippedBracketsLines, stripBrackets(line))
	}

	sortedLines := make([]string, 0, len(strippedBracketsLines))
	for _, line := range strippedBracketsLines {
		if len(line) > 0 {
			sortedLines = append(sortedLines, line)
		}
	}

	sort.Slice(sortedLines, func(i, j int) bool {
		iStatusCode, _ := strconv.Atoi(strings.Fields(sortedLines[i])[1])
		jStatusCode, _ := strconv.Atoi(strings.Fields(sortedLines[j])[1])
		return iStatusCode < jStatusCode
	})

	withUrls := make([]string, 0, len(sortedLines))
	for _, line := range sortedLines {
		url := strings.Fields(line)[0]
		url = strings.Replace(url, "https://", "", 1)
		url = strings.Replace(url, "http://", "", 1)
		withUrls = append(withUrls, url)
	}

	err = ioutil.WriteFile(sortedHttpxOutput, []byte(strings.Join(withUrls, "\n")+"\n"), 0644)
	checkErr(err)
	fmt.Printf("Sorted httpx results written to: %s\n", sortedHttpxOutput)
}

func scanNaabu(domain, resultDir string) {
	fmt.Println("Scanning subdomains with naabu...")
	sortedHttpxOutput := filepath.Join(resultDir, fmt.Sprintf("sorted_httpx_%s.txt", domain))
	naabuOutput := filepath.Join(resultDir, fmt.Sprintf("naabu_%s.txt", domain))
	cmd := exec.Command(filepath.Join("tools", "naabu"), "-list", sortedHttpxOutput, "-o", naabuOutput)
	showOutputInRealTime(cmd)
	cmd.Run()
	fmt.Printf("Naabu results written to: %s\n", naabuOutput)
}

func scanNuclei(domain, resultDir string) {
	fmt.Println("Scanning subdomains with nuclei...")
	sortedHttpxOutput := filepath.Join(resultDir, fmt.Sprintf("sorted_httpx_%s.txt", domain))
	nucleiOutput := filepath.Join(resultDir, fmt.Sprintf("nuclei_%s.txt", domain))
	cmd := exec.Command(filepath.Join("tools", "nuclei"), "-list", sortedHttpxOutput, "-o", nucleiOutput)
	showOutputInRealTime(cmd)
	cmd.Run()
	fmt.Printf("Nuclei results written to: %s\n", nucleiOutput)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("2nd argument not supplied")
		fmt.Println("2nd argument is the resolver file list path")
		fmt.Println("Usage : ./reconbulk domain resolvers_list")
		os.Exit(1)
	}

	configPath := "config.json"
	loadConfig(configPath)

	domain := os.Args[1]
	resolversFile := os.Args[2]
	dt := time.Now().Format("2006-01-02.15.04.05")
	reconDir := filepath.Join(os.Getenv("HOME"), "recon")
	resultDir := filepath.Join(reconDir, fmt.Sprintf("results/%s-%s", domain, dt))
	os.MkdirAll(resultDir, os.ModePerm)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("Keyboard interrupt detected. Exiting script...")
		os.Exit(1)
	}()

	amassCmd, subfinderCmd, assetfinderCmd, findomainCmd := findSubdomains(domain, resolversFile, resultDir)
	if amassCmd != nil {
		amassCmd.Wait()
	}
	if subfinderCmd != nil {
		subfinderCmd.Wait()
	}
	if assetfinderCmd != nil {
		assetfinderCmd.Wait()
	}
	if findomainCmd != nil {
		findomainCmd.Wait()
	}

	printBanner()
	scanCRT(domain, resultDir)
	combineSubdomains(domain, resultDir)
	findIPs(domain, resolversFile, resultDir)
	scanHttpx(domain, resultDir)
	scanNaabu(domain, resultDir)
	scanNuclei(domain, resultDir)
}
