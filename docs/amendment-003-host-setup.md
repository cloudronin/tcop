# Host setup: Mac mini and MacBook Pro

Two parts. Part 1 is what you do. Part 2 is what Claude does over SSH from
the study runner. **The first step that needs you at a machine is Part 1,
step 1, at the Mac mini.**

## Roles and names

| Machine | Role | Local hostname | Study identity | Evidence-link address |
| --- | --- | --- | --- | --- |
| Your laptop | Study runner only. Runs `tcop`, SSH, and the synthetic targets. Never host A or B. | unchanged | — | — |
| MacBook Pro | **Host A, Domain A** (observing side) | `tcop-a` | `TCOP_EXTERNAL_HOST_A=tcop-a` | `10.77.0.1` |
| Mac mini | **Host B, Domain B** (receiving side) | `tcop-b` | `TCOP_EXTERNAL_HOST_B=tcop-b` | `10.77.0.2` |

Why the Mac mini is B: B carries the heavy load (NemoClaw, OpenShell, the
Colima VM, and the E0/E1/E2 rows) and must never sleep. A desktop with no
lid or battery is the safer choice.

Each host keeps its own admin account and password, different from the
other host's. That is what "separately administered" means in the
admission record.

## Network

- **Evidence link, A to B: a Thunderbolt cable straight between the two
  hosts.** macOS shows it as "Thunderbolt Bridge". It carries only study
  traffic, with fixed addresses `10.77.0.1/30` (A) and `10.77.0.2/30` (B).
  `tcopd-b` listens on `10.77.0.2:8091` and nowhere else. The delay grid is
  applied here.
- **Management and targets: your home network.** Wi-Fi is fine. Claude
  reaches the hosts at `tcop-a.local` and `tcop-b.local` (Bonjour names, no
  router changes). The synthetic targets run on the study runner: to the
  hosts, the runner plays the outside world.
- **Wired versus Wi-Fi.** The A-to-B evidence link must be wired. Wi-Fi
  jitter is often several milliseconds, which would swamp the 10 ms delay
  cell. With the Thunderbolt link, baseline delay is well under 1 ms.
  Recommendation for the delay grid: keep the sealed interface delays (10,
  50, 100, 250 ms). Apply each one with macOS's built-in traffic shaper
  (`dnctl` and `pfctl`) on A's outbound traffic to `10.77.0.2:8091` only.
  Measure the link before each cell and log it. Never use application
  sleeps.

## Part 1: what you do

### At each machine (Mac mini first, then MacBook Pro)

1. **Create the study account.** System Settings > Users & Groups > Add
   User. Type: Administrator. Name: `tcop`. Use a strong password,
   different on each host. Do not sign this account into iCloud.
2. **Set the name and turn on SSH.** System Settings > General > Sharing:
   - Local hostname: `tcop-b` on the Mac mini, `tcop-a` on the MacBook Pro.
   - Remote Login: on. "Allow access for": only `tcop`. Leave "full disk
     access for remote users" off.
3. **Install pending macOS updates now**, then restart. Updates must not
   land during the study.
4. **MacBook Pro only:** plug in its power adapter and leave it plugged in
   for the whole study.
5. **Once, at either machine:** connect the Thunderbolt cable between the
   Mac mini and the MacBook Pro.

That is everything at the machines. The rest of your steps happen in a
terminal on your laptop.

### From your laptop (once per host; you type the passwords, Claude never sees them)

6. **Copy the study key to the host.** Claude creates the key first (Part
   2, step 1).
   `ssh-copy-id -i ~/.ssh/tcop_study.pub tcop@tcop-b.local`
   Type the host's `tcop` password once. Repeat for `tcop@tcop-a.local`.
7. **Install Homebrew.** `ssh -t tcop@tcop-b.local`, then paste the
   official one-line installer from brew.sh, type the password, and press
   Enter when asked. Repeat on `tcop-a.local`.
8. **Run the one-time privileged setup.** Claude writes
   `deploy/hosts/setup-host.sh` and shows it to you before you run it. You
   read it, then run
   `ssh -t tcop@tcop-b.local 'sudo bash -s B' < deploy/hosts/setup-host.sh`
   and type the password once. Repeat with `A` on `tcop-a.local`. It:
   - turns off SSH password login (key only from then on);
   - sets the Thunderbolt Bridge address;
   - sets sleep and power so the host cannot sleep;
   - turns off automatic macOS updates;
   - replaces macOS time sync with `chrony`;
   - installs the study's `pf` firewall anchor;
   - adds one narrow sudo rule, so that afterward Claude can only change
     the delay shaper (`/usr/sbin/dnctl`, `/sbin/pfctl`) without a
     password.
9. **Store the model provider key** (the agents need it):
   `ssh -t tcop@tcop-b.local 'umask 077; mkdir -p ~/.config/tcop; cat > ~/.config/tcop/provider.env'`
   Paste `OPENAI_API_KEY=...` and press Ctrl-D. Repeat on `tcop-a.local`.
   The harness passes this file to the agent processes only. Claude never
   prints or reads it, and it never enters the repository or the admission
   record. The earlier live runs used OpenAI; tell Claude if you want a
   different provider or model, since it is pinned at admission.
10. **Accept the NemoClaw notice and install it**, when Claude reaches Part
    2, step 5. Claude gives you one command per host. It runs NemoClaw's
    pinned installer with `--yes-i-accept-third-party-software` and your
    provider key. Running it is your acceptance of the notice (version
    `2026-04-01b`).

## Part 2: what Claude does over SSH

1. **Runner keys.** Create `~/.ssh/tcop_study` (ed25519) on the laptop, plus
   `~/.ssh/config` entries for `tcop-a` and `tcop-b` using that key only
   (`IdentitiesOnly yes`). After your step 8, confirm that key login works
   and password login is refused.
2. **Pinned prerequisites on both hosts** with Homebrew: `git`, Node 22
   (at least 22.19), Python 3.12, `colima`, the `docker` CLI, `chrony`, and
   `jq`. Record every version and bottle hash in the admission record.
3. **Container runtime.** Start Colima with fixed CPU and memory, check
   `docker info`, and check root access inside the Colima VM. B's instant
   egress cut needs that access. Colima, unlike Docker Desktop, needs no
   installer or license click.
4. **Clock sync.** `chrony` runs on both hosts. A syncs to Apple and public
   time servers and serves time on `10.77.0.0/30`. B syncs only to A, over
   the Thunderbolt link. Verification:
   - `chronyc tracking` and `chronyc sources` on both hosts;
   - an independent two-way timestamp exchange over the link before and
     after every session, written to the admission record (offset,
     round-trip time, method, time).
   The runner keeps normal macOS time sync. Its clock is not used for any
   cross-host metric.
5. **Pinned study stack.** Clone NemoClaw at
   `88fe14f3fb9a0bf72997cce19ec88b5b2ee08391`, then hand you the step 10
   command. After it finishes, verify OpenShell `0.0.116` (`d1155aa7`),
   OpenClaw `2026.9.2` inside the sandbox image, the sandbox identity, the
   policy tier, every preset hash, and the installed effective baseline
   policy hash. Install bare OpenClaw `2026.9.2` for E0 on B with its npm
   integrity check. Clone `tcop` at the study commit on both hosts and the
   runner, then run the tests.
6. **Firewall and ports.** Through the study's `pf` anchor:
   - B accepts TCP 8091 only on the Thunderbolt interface, only from
     `10.77.0.1`;
   - SSH (22) stays open on the home network for the runner;
   - nothing else is opened.
   The `tcopd` Python is added to macOS's application firewall on B. On the
   runner, macOS may ask once to allow incoming connections for the
   synthetic target server; that click is yours.
7. **Instant egress cut on B.** Install the deny-only filter worker in
   Colima's Linux VM, with its empty, preinstalled deny set (amendment 004).
8. **Sleep guard.** Check `pmset -g` and `pmset -g assertions` before every
   session. The runner holds `caffeinate` for the whole session.
9. **Admission capture.** Record host identities with a hash of each
   hardware UUID (never the raw value), the pins, the per-host notice
   version, the clock offset, and the link's baseline round-trip time and
   jitter.
10. **Conformance checks C1 to C4 on B.** Then calibrate the simulator and
    prepare the grid-finalization and expected-pattern records for you to
    seal.

## Notes

- **FileVault.** If a host restarts unattended (for example after a power
  cut), FileVault stops at the login screen until someone unlocks it at
  the machine. The study pauses until then. Planned restarts can use
  `fdesetup authrestart`, which needs your admin password.
- **Open item for you.** The maximum allowed clock offset between A and B
  is not yet pre-registered. Claude's recommendation is 1 ms, a tenth of
  the smallest delay cell, fixed in a sealed record before the first live
  episode.
