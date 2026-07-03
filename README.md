# The WPA3 Dragonblood Lab

This lab reproduces the Dragonblood attacks on WPA3's SAE handshake: a timing
side channel, a WPA3-to-WPA2 downgrade, and a full password recovery, all run
against a deliberately old, unpatched hostapd. Everything runs on virtual Wi-Fi
radios, so you don't need any wireless hardware to try it. Here's how to get it
going.

## What you'll need

You need Docker and make. On Linux you also need the `mac80211_hwsim` kernel
module, which ships with most distributions. macOS has no such module, so the lab
runs inside a small Linux VM instead: install Lima with `brew install lima` and
the Makefile will start the VM and forward every command into it for you. Either
way, the commands below are the same.

The access point is a pinned, pre-patch build of hostapd (the `hostap_2_4` tag)
set up for WPA3-SAE. Its password is fixed to `dr4gonfly` so the end-to-end runs
come out the same every time.

## Starting the lab

```bash
make up      # build the images and start the AP, client, and attacker
make test    # check that the client associates to the AP over SAE
```

`make up` handles the whole bring-up. On macOS it starts the Lima VM first, then
it loads the kernel module, builds the container images, launches the three
containers (access point, client, and attacker), and gives each one a virtual
radio. When you're done, `make down` stops the containers and `make teardown`
also unloads the kernel module.

## Running the attacks

There are three attacks, each behind a single make target:

```bash
make attack-timing      # the SAE timing side channel
make attack-downgrade   # the WPA3-to-WPA2 downgrade
make attack-recovery    # timing measurements turned into the actual password
```

Each one finds the AP's BSSID by itself and runs inside the attacker container.
The output lands in `results/<attack>/<timestamp>/`: the raw samples as a CSV,
the analysis as JSON, a metadata file for reproducibility, and a `plots/` folder.
If you would rather call the tools directly, they are installed as
`timing-attack`, `downgrade-attack`, and `recovery-attack`, and they share the
usual `--interface`, `--bssid`, `--ssid`, `--channel`, and `--output-dir`
options. Recovery also takes a `--dictionary`.

## Trying it against a real router

The `live-recovery` tool points the same recovery attack at a real access point
instead of the emulated one. On top of the attack it does the things a live
target needs: it puts your adapter into monitor mode, sweeps channels to find the
network, and prints a plain verdict at the end. Only ever run this against a
network you own or have explicit permission to test.

It needs a bare-metal Linux machine with a Wi-Fi adapter that can do monitor mode
and injection. It will not work through Docker or the Lima VM, because neither can
reach real Wi-Fi hardware.

```bash
sudo make attack-live IFACE=wlan0 SSID='HomeWiFi' DICT=/path/wordlist.txt
```

or, equivalently, by calling the module yourself:

```bash
sudo PYTHONPATH=. python -m attacks.dragonblood.live_recovery \
  --interface wlan0 --ssid 'HomeWiFi' --dictionary /path/wordlist.txt \
  --output-dir results
```

When it finishes it prints one of four verdicts:

| Verdict | What it means |
|---|---|
| `vulnerable-recovered` | The password was pinned down uniquely from the timing signal. |
| `vulnerable-partial` | There was a timing signal, but it narrowed the guesses without settling on one. |
| `patched-no-signal` | No signal above the noise. This is what a modern, constant-time router gives you, and it is the expected result. |
| `target-not-found` | The SSID never showed up on any channel that was swept. |

Two things are worth knowing. The channel sweep only covers 2.4 GHz by default
(channels 1, 6, and 11), so if your target is on 5 GHz you have to say so, for
example with `--channel 36`, or it simply will not find the network. And against
any up-to-date firmware you should expect `patched-no-signal`; that is the fix
working, not the tool failing. If you just want to watch the whole pipeline run
with no hardware at all, add `--dry-run`.

## Configuration

The interesting knob is `SAE_ITERATION_DELAY_US`. In emulation the kernel moves
frames around instantly, so the real hostapd finishes its password computation
far too fast to time. To make the side channel visible, the patched hostapd
sleeps for a set number of microseconds on each hash-to-curve iteration; that is
this variable, and it defaults to 3000 (3 ms). Lower it and the signal shrinks
toward the noise floor; raise it and the effect becomes easier to see.

You can also add jitter to the virtual link with `make netem PROFILE=noisy`. The
default profile is `clean`.

## Running without the lab

Every attack takes a `--dry-run` flag that swaps the real radio for an in-process
model. The model works out the true SAE iteration count for each password and MAC
and returns a plausible response time, so you get the complete attack and
analysis without Docker or the kernel module:

```bash
recovery-attack --dry-run --bssid 02:00:00:00:00:00 \
  --dictionary attacks/dragonblood/rockyou_100k.txt --output-dir results
```

## Tests

```bash
make test-unit   # the unit and integration tests; local, no VM or Docker
make test-e2e    # brings the lab up in transition mode and runs the e2e tests
```

There are 117 tests in all: 75 unit tests, 20 integration tests against the
modeling backend, and 22 end-to-end tests that drive the real Docker lab.
