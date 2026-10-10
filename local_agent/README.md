# Local Wi-Fi Connection Agent

A tiny, user-approved desktop agent that runs **on the visitor's own machine**
and is the only component that can touch the local Wi-Fi adapter.

## Why this exists

A Django website hosted on a server cannot control the Wi-Fi adapter of the
person browsing it — browsers deliberately forbid that. Connection commands are
therefore delegated to this agent, which:

* binds to `127.0.0.1` only (never reachable from the network),
* requires a shared secret header (`X-Agent-Secret`) matching
  `WIFI_LOCAL_AGENT_SHARED_SECRET` in `config/settings.py`,
* accepts only well-formed SSIDs that were previously scanned by the server,
* builds argument lists for `netsh` / `nmcli` **without ever using a shell**,
* never writes Wi-Fi passwords to disk or logs (the temporary Windows profile
  file is created with restrictive permissions and deleted immediately).

## Run it

```powershell
python local_agent/agent.py
# optional:
python local_agent/agent.py --port 8765 --secret "my-shared-secret"
```

## Endpoints

| Method | Path           | Body                            | Purpose                     |
|--------|----------------|---------------------------------|-----------------------------|
| GET    | `/status`      | –                               | Health check                |
| POST   | `/connect`     | `{"ssid": "...", "password": "..."}` | Connect to a network  |
| POST   | `/disconnect`  | –                               | Disconnect current network  |

Passwords are held in memory only for the duration of the command.
