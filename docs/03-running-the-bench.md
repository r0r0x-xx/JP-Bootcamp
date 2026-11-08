# 3. Running the bench

Three processes, in one order:

```
   FlatSat  --USB-->  [ Space IDS ]  --TCP 5010-->  PWNSAT-C3
                           :5011                       :8000
                       its console                 the dashboard
```

**The sensor starts first and it takes the serial port exclusively.** Nothing
else may open the port, not C3, not an attack script, not `screen`. If C3
grabs the port first, the sensor cannot have it, and every attack you run
afterwards goes uninspected. An empty alert list then looks exactly like a
detector that does not work.

---

## By hand

This is the recommended way for the workshop. You see what each process says,
and you can stop one without touching the others.

Three terminals. **Each one needs `source .venv/bin/activate` first.**

### Terminal 1, the sensor

```sh
cd JP-Bootcamp
source .venv/bin/activate
cd ids && ./run.sh run
```

```
  FlatSat --USB--> [ Space IDS ] --> PWNSAT-C3
  board      /dev/ttyACM1 @ 921600
  downstream 127.0.0.1:5010   <- point C3 here
  console    http://127.0.0.1:5011
  mode       detect
```

Leave it running. Alerts print here as they happen, and the same ones go to the
console at **http://127.0.0.1:5011**.

### Terminal 2, the ground console

```sh
cd JP-Bootcamp
source .venv/bin/activate
cd c3
PWNSAT_C3_IDS_ENDPOINT=127.0.0.1:5010 uvicorn backend.app:app --port 8000
```

Open **http://127.0.0.1:8000** and log in with `operator` / `pwnsat`.

`PWNSAT_C3_IDS_ENDPOINT` is the whole trick: it tells C3 to talk to the sensor
instead of to the board. The sensor speaks exactly the framing the board
speaks, so nothing above the transport knows the difference.

### Terminal 3, your attacks

```sh
cd JP-Bootcamp
source .venv/bin/activate
cd attacks
FLATSAT_HOST=1 python3 00_recon_apid_enum/00_recon_apid_enum_usb.py
```

`FLATSAT_HOST=1` sends the attack **through the sensor**. Without it, the
attack talks to the board directly, the sensor never sees it, and no rule
fires. See [running the attacks](04-attacks.md).

### Stopping

`Ctrl-C` in each terminal, sensor last. C3 reconnects on its own if the sensor
comes back, so you can restart the sensor without touching C3.

---

## As a service

For a machine that should come up ready, a classroom image, or a box in the
corner you do not want to babysit.

### Install

```sh
# Put the repository somewhere systemd-appropriate
sudo mkdir -p /opt
sudo cp -r ~/JP-Bootcamp /opt/JP-Bootcamp

# An account to run it, in dialout so it can open the board
sudo useradd --system --home /opt/JP-Bootcamp --shell /usr/sbin/nologin pwnsat
sudo usermod -aG dialout pwnsat
sudo chown -R pwnsat:pwnsat /opt/JP-Bootcamp

# Build the environment as that user
sudo -u pwnsat python3 -m venv /opt/JP-Bootcamp/.venv
sudo -u pwnsat /opt/JP-Bootcamp/.venv/bin/pip install -r /opt/JP-Bootcamp/requirements.txt

# The units
sudo cp /opt/JP-Bootcamp/systemd/pwnsat-ids.service /etc/systemd/system/
sudo cp /opt/JP-Bootcamp/systemd/pwnsat-c3.service  /etc/systemd/system/
sudo systemctl daemon-reload
```

If you put the repository somewhere other than `/opt/JP-Bootcamp`, or run it as
a user other than `pwnsat`, fix the paths:

```sh
sudo sed -i 's#/opt/JP-Bootcamp#/your/path#g; s/^User=pwnsat/User=youruser/' \
    /etc/systemd/system/pwnsat-ids.service /etc/systemd/system/pwnsat-c3.service
sudo systemctl daemon-reload
```

### Start, stop, restart, status

```sh
sudo systemctl start   pwnsat-ids      # start the sensor
sudo systemctl start   pwnsat-c3       # then the console

sudo systemctl stop    pwnsat-c3       # stop in the reverse order
sudo systemctl stop    pwnsat-ids

sudo systemctl restart pwnsat-ids      # restart just the sensor
sudo systemctl restart pwnsat-ids pwnsat-c3

sudo systemctl status  pwnsat-ids      # is it up, and what did it last say
```

### Start automatically at boot

```sh
sudo systemctl enable  pwnsat-ids pwnsat-c3     # on at boot
sudo systemctl disable pwnsat-ids pwnsat-c3     # off again

sudo systemctl enable --now pwnsat-ids          # enable and start in one go
```

### Logs

```sh
journalctl -u pwnsat-ids -f              # follow the sensor live
journalctl -u pwnsat-ids -n 100          # the last hundred lines
journalctl -u pwnsat-ids --since "10 min ago"
journalctl -u pwnsat-ids -p err          # errors only
journalctl -u pwnsat-ids -u pwnsat-c3 -f # both, interleaved
```

### Both at once

There is no wrapper script on purpose. These two lines are the whole thing:

```sh
sudo systemctl restart pwnsat-ids pwnsat-c3
sudo systemctl status  pwnsat-ids pwnsat-c3 --no-pager
```

---

## Which port is which

| Port | What listens | What it is for |
|---|---|---|
| `127.0.0.1:5010` | Space IDS | The frame stream. **C3 attaches here.** Not a web page |
| `127.0.0.1:5011` | Space IDS | **The sensor's console**, in a browser |
| `127.0.0.1:8000` | PWNSAT-C3 | The ground dashboard, in a browser |

A common early mistake is pointing a browser at `:5010` and finding nothing.
That port carries raw frames, not HTML. The console is `:5011`.

All three bind to `127.0.0.1` only. Nothing is reachable from the network, by
design: the dashboard ships with demo credentials and is not meant to be
exposed.

---

## Changing how the sensor runs

```sh
./run.sh run --mode block          # drop what alerts, instead of forwarding it
./run.sh run --port /dev/ttyACM1   # skip auto-detection
./run.sh run --stock-firmware      # you flashed the radio build on purpose
./run.sh replay all                # no hardware: the captures against the rules
./run.sh boards                    # what this machine can see
```

**`detect` is the default and should stay the default for the labs.** A bench
where the attack never lands teaches nothing. `--mode block` exists to
demonstrate the mitigation in lab form.

`--stock-firmware` turns off the `radio-origin-frame` rule. On a course build
that rule can never fire, so if you are seeing it, either the board is not
running the course firmware or the event stream is not coming from the board.
Do not reach for this flag to silence it, find out why first.

---

## The order, and why it is not negotiable

1. **Sensor first.** It opens the serial port exclusively.
2. **C3 second**, pointed at `127.0.0.1:5010`.
3. **Attacks last**, with `FLATSAT_HOST=1`.

If C3 is already holding the port when the sensor starts, the sensor reports
that it cannot open the board. Stop C3, start the sensor, start C3 again.

**If the sensor dies, C3 goes blind.** That is what an in-line detector does;
it is not a fault. It is also what a real deployment looks like, where
the thing in the middle is a single point of failure you have to plan for.

---

Next: [**4. Running the attacks**](04-attacks.md)
