![banner](https://github.com/11notes/defaults/blob/main/static/img/banner.png?raw=true)

# SYNOPSIS 📖
**What can I do with this?** tini-pm can start and monitor multiple processes unlike tini itself that can only start a single process. Process definition is done via environment variable and allows for fine grained control over the process lifecycle. A process can fail and reap all processes within the container or tini-pm will try to indefinitely restart the process in a configurable interval. It’s meant as an alternative to the bloated s6 that only works as root.


# COMMAND LINE 📟
* **--restart-delay** - The delay before restarting a process that died in seconds, by default *5 seconds*
* **--socket** - enable socket communication with the container, to be able to execute commands from other containers
* **--socket-file** - path to socket file, by default */run/tini-pm/tini-pm.sock*

# YAML DATA STRUCTURE 📦
This example will start two node applications, but only the important one will fail the entire container if the process dies. The first development app can fail and the container will still keep running. All environment variables from the container will be copied into the process plus the additional ```NODE_ENV```.
```yaml
services:
  - name: "my development node js app"
    bin: "/usr/local/bin/node"
    arguments: [
      "/node/dev.js"
    ]
    environment:
      NODE_ENV: "development"

  - name: "my important node app"
    fail: true
    bin: "/usr/local/bin/node"
    arguments: [
      "/node/important.js"
    ]
    environment:
      NODE_ENV: "production"
```