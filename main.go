package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"github.com/gorilla/mux"
	"github.com/shirou/gopsutil/v4/process"
	yaml "gopkg.in/yaml.v3"
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
	killUnknownChildProcesses()
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
				log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) with arguments %v died (restarting every )", bin, cmd.Process.Pid, args))
				time.Sleep(time.Duration(restartDelay) * time.Second) 
				run(name, bin, args, fail, restart, environment, restartdelayp)
			}else{
				log(LOG_CALLER_MAIN, fmt.Sprintf("process %s (PID %d) with arguments %v died", bin, cmd.Process.Pid, args))
			}
		}
	}
}

func socket(pfile *string){
	var file string = *pfile;
	r := mux.NewRouter()
	r.HandleFunc("/", socketPost).Methods("POST")
	r.HandleFunc("/", socketGet).Methods("GET")
 
	srv := &http.Server{
	 Handler: r,
	}

	err := os.Remove(file) 
	unix, err := net.Listen("unix", file)
	if err != nil {
		panic(err)
	}
	log(LOG_CALLER_MAIN, fmt.Sprintf("started socket on %s", file))
	go srv.Serve(unix)
}

func socketGet(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "post json with bin and args (array)")
}
 
func socketPost(w http.ResponseWriter, r *http.Request) {
	var p SocketPost
	err := json.NewDecoder(r.Body).Decode(&p)

	if err != nil {  
		http.Error(w, err.Error(), http.StatusBadRequest)  
		return
	} 

	data, err := exec.Command(p.Bin, p.Args...).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)  
		return
	}

	fmt.Fprintf(w, string(data))
}

func main() {
	// syscalls
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGTERM, syscall.SIGSTOP, syscall.SIGINT)

	// event listener
	go func() {
		<-signalChannel
		killKnownChildProcesses()
	}()

	// parse flags
	restartDelay := flag.Int("restart-delay", 5, "restart delay in seconds for proccesses with restart true")
	enableSocket := flag.Bool("socket", false, "enable socket for communication")
	socketFile := flag.String("socket-file", "/run/tini-pm/tini-pm.sock", "path to socket file")
	flag.Parse()

	// parse config
	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(os.Getenv("TINI_PM_CONFIG")), cfg); err != nil {
		log(LOG_CALLER_MAIN, fmt.Sprintf("yaml parse error %v", err))
		os.Exit(EXIT_YML_PARSE_ERROR)
	}

	// start socket if set
	if(*enableSocket){
		socket(socketFile)
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