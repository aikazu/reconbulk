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
	"sync"
	"syscall"
	"text/template"
	"time"
)

type Config struct {
	Tools struct {
		Amass      ToolConfig `json:"amass"`
		Subfinder  ToolConfig `json:"subfinder"`
		Assetfinder ToolConfig `json:"assetfinder"`
		Findomain  ToolConfig `json:"findomain"`
		Massdns    ToolConfig `json:"massdns"`
		Httpx      ToolConfig `json:"httpx"`
		Naabu      ToolConfig `json:"naabu"`
		Nuclei     ToolConfig `json:"nuclei"`
		Crtsh      struct {
			URL string `json:"url"`
		} `json:"crtsh"`
	} `json:"tools"`
	Directories struct {
		ReconDir   string `json:"reconDir"`
		ResultsDir string `json:"resultsDir"`
	} `json:"directories"`
}

type ToolConfig struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func loadConfig(configFile string) (*Config, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func renderTemplate(templateStr string, data interface{}) (string, error) {
	tmpl, err := template.New("config").Parse(templateStr)
	if err != nil {
		return "", err
	}

	var rendered strings.Builder
	err = tmpl.Execute(&rendered, data)
	if err != nil {
		return "", err
	}

	return rendered.String(), nil
}

func startCmd(config ToolConfig, data map[string]string) *exec.Cmd {
	toolsDir := "tools"
	data["toolsDir"] = toolsDir

	args := make([]string, len(config.Args))
	for i, arg := range config.Args {
		renderedArg, err := renderTemplate(arg, data)
		if err != nil {
			log.Fatalf("Failed to render template: %v", err)
		}
		args[i] = renderedArg
	}
	cmd := exec.Command(filepath.Join(toolsDir, config.Path), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
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

func checkErr(err error, context string) {
	if err != nil {
		log.Fatalf("%s: %v", context, err)
	}
}

func executeCmd(cmd *exec.Cmd, wg *sync.WaitGroup) {
	defer wg.Done()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("Error running %s: %v", cmd.String(), err)
	}
}

func findSubdomains(config *Config, domain, resolversFile, resultDir string, wg *sync.WaitGroup) {
	defer wg.Done()

	data := map[string]string{
		"domain":       domain,
		"resolversFile": resolversFile,
		"outputDir":    resultDir,
	}

	tools := []ToolConfig{
		config.Tools.Amass,
		config.Tools.Subfinder,
		config.Tools.Assetfinder,
		config.Tools.Findomain,
	}

	var cmdWg sync.WaitGroup
	for _, tool := range tools {
		data["outputFile"] = filepath.Join(resultDir, fmt.Sprintf("%s_%s.txt", tool.Path, domain))
		cmd := startCmd(tool, data)
		cmdWg.Add(1)
		go executeCmd(cmd, &cmdWg)
	}

	cmdWg.Wait()
}

func scanCRT(config *Config, domain, resultDir string) {
	fmt.Println("Scanning crt.sh...")
	crtOutput := filepath.Join(resultDir, fmt.Sprintf("%s.crt.txt", domain))
	crtURL := fmt.Sprintf(config.Tools.Crtsh.URL, domain)

	response, err := exec.Command("curl", "-s", crtURL).Output()
	checkErr(err, "Failed to get response from crt.sh")

	var data []map[string]interface{}
	err = json.Unmarshal(response, &data)
	checkErr(err, "Failed to unmarshal crt.sh response")

	uniqueSubdomains := make(map[string]struct{})
	for _, entry := range data {
		if nameValue, ok := entry["name_value"].(string); ok && nameValue != "" {
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
	files := []string{"amass", "subfinder", "assetfinder", "findomain", "crt"}
	uniqueSubdomains := make(map[string]struct{})

	for _, prefix := range files {
		file := filepath.Join(resultDir, fmt.Sprintf("%s_%s.txt", prefix, domain))
		if fileExists(file) {
			lines, err := ioutil.ReadFile(file)
			checkErr(err, fmt.Sprintf("Failed to read file: %s", file))
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

	subdomainsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.subdomains.txt", domain))
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
	checkErr(err, "Failed to write unique subdomains to file")
}

func findIPs(config *Config, domain, resolversFile, resultDir string) {
	fmt.Println("Now finding IPs for subdomains...")
	subdomainsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.subdomains.txt", domain))
	ipsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.ips.txt", domain))

	data := map[string]string{
		"resolversFile": resolversFile,
		"inputFile":     subdomainsOutput,
		"outputFile":    ipsOutput,
	}

	cmd := startCmd(config.Tools.Massdns, data)
	executeCmd(cmd, &sync.WaitGroup{})
	fmt.Printf("IPs written to: %s\n", ipsOutput)
}

func stripANSI(text string) string {
	ansi := regexp.MustCompile(`\x1B(?:[@-Z\\-_]]|\[[0-?]*[ -/]*[@-~])`)
	return ansi.ReplaceAllString(text, "")
}

func stripBrackets(text string) string {
	return strings.Replace(strings.Replace(text, "[", "", -1), "]", "", -1)
}

func scanHttpx(config *Config, domain, resultDir string) {
	fmt.Println("Scanning subdomains with httpx...")
	subdomainsOutput := filepath.Join(resultDir, fmt.Sprintf("%s.subdomains.txt", domain))
	httpxOutput := filepath.Join(resultDir, fmt.Sprintf("httpx_%s.txt", domain))

	data := map[string]string{
		"inputFile":  subdomainsOutput,
		"outputFile": httpxOutput,
	}

	cmd := startCmd(config.Tools.Httpx, data)
	executeCmd(cmd, &sync.WaitGroup{})
	fmt.Printf("Httpx results written to: %s\n", httpxOutput)

	fmt.Println("Sorting httpx results...")
	sortedHttpxOutput := filepath.Join(resultDir, fmt.Sprintf("sorted_httpx_%s.txt", domain))

	linesBytes, err := ioutil.ReadFile(httpxOutput)
	checkErr(err, "Failed to read httpx output")
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
	checkErr(err, "Failed to write sorted httpx results to file")
	fmt.Printf("Sorted httpx results written to: %s\n", sortedHttpxOutput)
}

func scanNaabu(config *Config, domain, resultDir string) {
	fmt.Println("Scanning subdomains with naabu...")
	sortedHttpxOutput := filepath.Join(resultDir, fmt.Sprintf("sorted_httpx_%s.txt", domain))
	naabuOutput := filepath.Join(resultDir, fmt.Sprintf("naabu_%s.txt", domain))

	data := map[string]string{
		"inputFile":  sortedHttpxOutput,
		"outputFile": naabuOutput,
	}

	cmd := startCmd(config.Tools.Naabu, data)
	executeCmd(cmd, &sync.WaitGroup{})
	fmt.Printf("Naabu results written to: %s\n", naabuOutput)
}

func scanNuclei(config *Config, domain, resultDir string) {
	fmt.Println("Scanning subdomains with nuclei...")
	sortedHttpxOutput := filepath.Join(resultDir, fmt.Sprintf("sorted_httpx_%s.txt", domain))
	nucleiOutput := filepath.Join(resultDir, fmt.Sprintf("nuclei_%s.txt", domain))

	data := map[string]string{
		"inputFile":  sortedHttpxOutput,
		"outputFile": nucleiOutput,
	}

	cmd := startCmd(config.Tools.Nuclei, data)
	executeCmd(cmd, &sync.WaitGroup{})
	fmt.Printf("Nuclei results written to: %s\n", nucleiOutput)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage : ./reconbulk domain resolvers_list")
		os.Exit(1)
	}

	config, err := loadConfig("config.json")
	checkErr(err, "Failed to load config")

	domain := os.Args[1]
	resolversFile := os.Args[2]
	dt := time.Now().Format("2006-01-02.15.04.05")
	reconDir := filepath.Join(os.Getenv("HOME"), "recon")
	resultDir := filepath.Join(reconDir, fmt.Sprintf("results/%s-%s", domain, dt))
	err = os.MkdirAll(resultDir, os.ModePerm)
	checkErr(err, "Failed to create result directory")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("Keyboard interrupt detected. Exiting script...")
		os.Exit(1)
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go findSubdomains(config, domain, resolversFile, resultDir, &wg)
	wg.Wait()

	printBanner()
	scanCRT(config, domain, resultDir)
	combineSubdomains(domain, resultDir)
	findIPs(config, domain, resolversFile, resultDir)
	scanHttpx(config, domain, resultDir)
	scanNaabu(config, domain, resultDir)
	scanNuclei(config, domain, resultDir)
}
