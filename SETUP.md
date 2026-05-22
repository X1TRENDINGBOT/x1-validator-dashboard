# X1 Validator Dashboard — SSH-tunnel setup (no open port, no password)

Single-file, dependency-free monitor for the Tachyon validator.
Terminal-style UI. Binds to localhost only — nothing exposed to the internet.
You view it through an SSH tunnel using your existing SSH access.

## 1. Put the file on the validator (public repo)
    cd /home/shezi
    curl -L -o dashboard.js https://raw.githubusercontent.com/<YOUR_USERNAME>/x1-validator-dashboard/main/dashboard.js
    head -5 dashboard.js   # should show "#!/usr/bin/env node"

## 2. Confirm node path (for systemd)
    which node
If not /usr/bin/node, use that path in ExecStart below.

## 3. nft counter needs passwordless sudo (you already have it)
    sudo -n nft list ruleset   # must not prompt

## 4. Test it (foreground)
    node /home/shezi/dashboard.js
Binds to 127.0.0.1:8088 only and prints the SSH-tunnel command. Ctrl-C to stop.

## 5. Open it from YOUR computer (SSH tunnel)
    ssh -L 8088:localhost:8088 shezi@91.244.71.20
Leave it open, then browse to:  http://localhost:8088/
No password, no open port — reachable only through your SSH connection.

## 6. Run permanently (systemd)
    sudo tee /etc/systemd/system/valdash.service > /dev/null << 'UNIT'
    [Unit]
    Description=X1 Validator Dashboard
    After=network.target

    [Service]
    Type=simple
    User=shezi
    Environment=DASH_BIND=127.0.0.1
    Environment=DASH_PORT=8088
    Environment=DASH_LEDGER=/home/shezi/x1/ledger
    Environment=DASH_ACCOUNTS=/mnt/accounts
    Environment=DASH_LOG=/home/shezi/x1/log.txt
    Environment=DASH_RPC_COUNTER_LOG=/home/shezi/rpc_counter.log
    ExecStart=/usr/bin/node /home/shezi/dashboard.js
    Restart=always
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
    UNIT
    sudo systemctl daemon-reload
    sudo systemctl enable --now valdash
    sudo systemctl status valdash

## Updating later
Push new dashboard.js to the repo, then:
    cd /home/shezi && curl -L -o dashboard.js https://raw.githubusercontent.com/<YOUR_USERNAME>/x1-validator-dashboard/main/dashboard.js && sudo systemctl restart valdash

## If you ever want anywhere/phone access instead of SSH
    Environment=DASH_PASSWORD=choose-a-strong-pass
    Environment=DASH_BIND=0.0.0.0
    sudo ufw allow 8088/tcp     # or restrict: from <YOUR_IP> to any port 8088 proto tcp
The dashboard REFUSES to run password-less on a non-localhost bind.

## Phone via SSH
Use Termius (or any SSH app with port forwarding): forward 8088 -> localhost:8088
on the validator host, connect, then open http://localhost:8088 in the browser.

## What it shows
status/uptime/cpu/ram, health/slot, net lag, rpc load (nft counter + hourly
trend), disk ledger+accounts bars, TCP connections, recent log warnings/errors.
Auto-refresh 15s. All read locally — no Railway, no database.
