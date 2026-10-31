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
cd $HOME/Games/openol-relay
podman build --no-cache -t openol-relay:latest -f Container/Containerfile .
```

### Running the Container

Disclaimer: If you're gonna use a custom config put it into the root of this repository.

Run the container with:

```sh
podman run --replace -it \
  --name openol-relay \
  -p 7777:7777/tcp \
  -p 7777:7777/udp \
  openol-relay:latest
```

### Simulator secret

A headless enemy AI process (`-simnode`) is admitted only if it proves it knows the secret in the
relay's `OPENOL_SIM_SECRET` environment variable. Without the variable the relay refuses all simulators,
and enemy AI runs on one of the players.

```
podman run -e OPENOL_SIM_SECRET="$(cat sim_secret.txt)" ...
```

Room passwords and this secret are never sent over the network; all traffic is encrypted. Old game
versions cannot connect to this relay: the handshake changed.

### Server key and passwords

On first start the relay creates `relay.db.key` next to `relay.db` and logs `Server key: <hex>`.
Clients remember the key per address on first connection and refuse the server if it changes, like SSH.

* Keep the file and back it up. In a container, put `relay.db` and `relay.db.key` on a volume, otherwise
  every new container is a new server to all clients.
* To protect the first connection too, publish the key and have players add it to `OLMultiplayer.ini`
  before connecting:
  ```
  [OLGame.OLKnownServers]
  relay.example.com:7777=<hex>
  ```
* If the key is lost, clients must delete that line, and room passwords must be set again with `setpw`:
  they are stored as Argon2 hashes bound to the key. Plain passwords in an older `relay.db` are
  converted on start.
* A leaked `relay.db` lets someone join those rooms, but does not reveal the passwords themselves.

### Monitoring

The `stats` command and the GUI's Stats tab show traffic, refused joins, datagrams that failed
authentication, and per player RTT, resends and rule violations. The log gets a summary every minute.
