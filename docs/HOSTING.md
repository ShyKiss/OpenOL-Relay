# Running relay

### Prerequisites

Warning: Run everything here within a tmux session if you'd like it to continue running once you log out of ssh

Ensure the following dependencies are installed on your host:

* podman
* tmux
* git
* text editor (e.g. vim)

### Podman Setup

On the machine that will host the dedicated server, execute the following commands individually:

```sh
mkdir -p $HOME/Games/OpenOL-Relay
git clone https://github.com/ShyKiss/OpenOL-Relay $HOME/Games/OpenOL-Relay
cd $HOME/Games/OpenOL-Relay/Container
podman build --no-cache -t OpenOL-Relay:latest .
```

### Running the Container

Run the container with:

```sh
podman run --replace -it \
  --name OpenOL-Relay \
  -p 7777:7777/tcp \
  -p 7777:7777/udp \
  -v "$HOME/Games:/opt/games" \
  OpenOL-Relay:latest
```

Type exit once it gets into a shell.

Start the container by running

```sh
podman start -ai OpenOL-Relay
```

To start your server, run:
```sh
entrypoint.sh
```
