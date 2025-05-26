package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"github.com/shirou/gopsutil/v4/process"
	yaml "gopkg.in/yaml.v3"
	"io/ioutil"
)

const EXIT_YML_PARSE_ERROR = 11;
const EXIT_REQUIRED_PROCESS_FAIL = 12;
const EXIT_CANT_KILL_RUNAWAY = 13;
const EXIT_NO_CMD_ROOT = 14;
const TINI_PM_CONFIG = "/etc/tini-pm/config.yml"
const LOG_CALLER_MAIN = "tini-pm"

var childProcesses = make(map[string]ProcessInfo)
var wg sync.WaitGroup
var logMaxNameLength int

type Config struct {
	Services []struct {
		Name string `yaml:"name"`
		Fail bool `yaml:"fail"`
		Restart bool `yaml:"restart"`
		Bin string `yaml:"bin"`
		Arguments []string `yaml:"arguments"`
		Environment map[string]interface{} `yaml:"environment"`
	} `yaml:"services"`
}

type ProcessInfo struct {
	cmd *exec.Cmd
	Bin string
	Arguments []string
	Fail bool
	PID int
	Hash string
}

type SocketPost struct {
	Bin string `json:"bin"`
	Args []string `json:"args"`
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func log(caller string, msg string){
	var spaces string
	for i := 1; i <= logMaxNameLength - len(caller); i++ {
		spaces += " "
	}
	fmt.Fprintf(os.Stdout, "%s%s | %s\n", caller, spaces, msg)
}

func killKnownChildProcesses(){
	for _, child := range childProcesses {		
		if err := syscall.Kill(-child.cmd.Process.Pid, syscall.SIGTERM); err == nil {
			log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) terminated successfully", child.Bin, child.PID))
		}else{
			log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) could not be terminated. ERROR: %s", child.Bin, child.PID, err))
		}
	}
}

func killUnknownChildProcesses(){
	processes, err := process.Processes()
	if err == nil {
		for _, p := range processes {
			name, _ := p.Name()
			if p.Pid != 1 {
				if err := p.Kill(); err == nil {
					log(LOG_CALLER_MAIN, fmt.Sprintf("unknown process %s (PID %d) killed", name, p.Pid))
				}
			}
		}
		os.Exit(EXIT_REQUIRED_PROCESS_FAIL)
	}else{
		os.Exit(EXIT_CANT_KILL_RUNAWAY);
	}
}

func run(name string, bin string, args []string, fail bool, restart bool, environment map[string]interface{}, restartdelayp *int){
	var restartDelay int = *restartdelayp	
	defer wg.Done()

	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid:true}
	if(len(environment) <= 0){
		cmd.Env = os.Environ()
	}else{
		env := append(os.Environ())
		for key, value := range environment {
			env = append(env, fmt.Sprintf("%s=%v", key, value))
		}
		cmd.Env = env
	}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	go func() {
		stdoutScanner := bufio.NewScanner(io.MultiReader(stdout,stderr))
		for stdoutScanner.Scan() {
			log(name, stdoutScanner.Text())
		}
	}()

	h := sha256.New()
	h.Write([]byte(name + bin))
	hash := hex.EncodeToString(h.Sum(nil))

	err := cmd.Start()
	if err != nil {
		log(LOG_CALLER_MAIN, fmt.Sprintf("process %s with arguments %v could not be started. ERROR: %s", bin, args, err))
	}else{
		log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) with arguments %v started", bin, cmd.Process.Pid, args))
		childProcesses[hash] = ProcessInfo{
			cmd: cmd,
			Bin: bin,
			Arguments: args,
			Fail: fail,
			PID: cmd.Process.Pid,
		}

		err = cmd.Wait()
		if err != nil {
			if(fail){
				killKnownChildProcesses()
				os.Exit(EXIT_REQUIRED_PROCESS_FAIL)
			}else if(restart){
				log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) with arguments %v died (restarting every %ds)", bin, cmd.Process.Pid, args, restartDelay))
				time.Sleep(time.Duration(restartDelay) * time.Second) 
				go run(name, bin, args, fail, restart, environment, restartdelayp)
			}else{
				log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) with arguments %v died", bin, cmd.Process.Pid, args))
			}
		}
	}
}

func main() {
	// syscalls
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGTERM, syscall.SIGSTOP, syscall.SIGINT)

	// event listener
	go func() {
		signal := <-signalChannel
		log(LOG_CALLER_MAIN, fmt.Sprintf("received signal %v", signal))
		killKnownChildProcesses()
		killUnknownChildProcesses()
	}()

	// parse flags
	restartDelay := flag.Int("restart-delay", 5, "restart delay in seconds for proccesses with restart true")
	enableSocket := flag.Bool("socket", false, "enable socket for communication")
	flag.Parse()

	// check if environment variable provided is a file or inline and parse accordingly
	cfg := &Config{}
	file, err := ioutil.ReadFile(getEnv("TINI_PM_CONFIG", TINI_PM_CONFIG))
	if err != nil{
		if err := yaml.Unmarshal([]byte(getEnv("TINI_PM_CONFIG", TINI_PM_CONFIG)), cfg); err != nil {
			log(LOG_CALLER_MAIN, fmt.Sprintf("yaml parse error. ERROR: %s", err))
			os.Exit(EXIT_YML_PARSE_ERROR)
		}
	}else{
		if err := yaml.Unmarshal(file, cfg); err != nil {
			log(LOG_CALLER_MAIN, fmt.Sprintf("yaml parse error. ERROR: %s", err))
			os.Exit(EXIT_YML_PARSE_ERROR)
		}
	}
	

	// start socket if set
	if(*enableSocket){
		if _, err := os.Stat("/run/cmd"); !os.IsNotExist(err) {
			logMaxNameLength = len("cmd-socket")
			wg.Add(1)
			go run("cmd-socket", "cmd-socket", nil, false, true, nil, restartDelay)
		}else{
			log(LOG_CALLER_MAIN, fmt.Sprintf("can't start cmd-socket. ERROR: folder /run/cmd does not exist!"))
			os.Exit(EXIT_NO_CMD_ROOT)
		}
	}

	// start processes
	for _, service := range cfg.Services {
		if(len(service.Name) > logMaxNameLength){
			logMaxNameLength = len(service.Name)
		}
	}

	for _, service := range cfg.Services {
		wg.Add(1)
		go run(service.Name, service.Bin, service.Arguments, service.Fail, service.Restart, service.Environment, restartDelay)
	}

	// wait for all processes to complete
	wg.Wait()

	// exit tini-pm
	os.Exit(0)
}