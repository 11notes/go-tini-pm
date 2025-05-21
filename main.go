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

const LOG_CALLER_MAIN = "tini-pm"

var childProcesses = make(map[string]ProcessInfo)
var wg sync.WaitGroup
var logMaxNameLength int

type Config struct {
	Services []struct {
		Name string `yaml:"name"`
		Fail bool `yaml:"fail,omitempty"`
		Restart bool `yaml:"restart,omitempty"`
		Bin string `yaml:"bin"`
		Arguments []string `yaml:"arguments,omitempty"`
		Environment map[string]interface{} `yaml:"environment,omitempty"`
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
	Bin string `json:"bin,omitempty"`
	Args []string `json:"args,omitempty"`
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
		if err := child.cmd.Process.Kill(); err == nil {
			log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) killed", child.Bin, child.PID))
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
		log(LOG_CALLER_MAIN, fmt.Sprintf("process %s with arguments %v could not be started %v", bin, args, err))
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
	file, err := ioutil.ReadFile(os.Getenv("TINI_PM_CONFIG"))
	if err != nil{
		if err := yaml.Unmarshal([]byte(os.Getenv("TINI_PM_CONFIG")), cfg); err != nil {
			log(LOG_CALLER_MAIN, fmt.Sprintf("yaml parse error %v", err))
			os.Exit(EXIT_YML_PARSE_ERROR)
		}
	}else{
		if err := yaml.Unmarshal(file, cfg); err != nil {
			log(LOG_CALLER_MAIN, fmt.Sprintf("yaml parse error %v", err))
			os.Exit(EXIT_YML_PARSE_ERROR)
		}
	}
	

	// start socket if set
	if(*enableSocket){
		logMaxNameLength = len("cmd-socket")
		wg.Add(1)
		go run("cmd-socket", "cmd-socket", nil, false, true, nil, restartDelay)
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