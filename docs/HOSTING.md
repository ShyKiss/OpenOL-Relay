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
mkdir -p $HOME/Games/openol-relay
git clone https://github.com/ShyKiss/openol-relay $HOME/Games/openol-relay
cd $HOME/Games/openol-relay/Container
podman build --no-cache -t openol-relay:latest -f Container/Containerfile .
```

### Running the Container

Run the container with:

```sh
podman run --replace -it \
  --name openol-relay \
  -p 7777:7777/tcp \
  -p 7777:7777/udp \
  -v "$HOME/Games:/opt/games" \
  openol-relay:latest
```
