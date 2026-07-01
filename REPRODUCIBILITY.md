# Reproducibility — recreating the lab

How to stand up the whole system from scratch. **Hybrid design:** the framework
and the Kali attacker run as **Docker containers**; the Metasploitable 3 target
runs as a **VM** (Vagrant).

```
┌─────────────────────────── docker compose ───────────────────────────┐
│   app  (lgg_automation)  ──SSH:22 / RPC:55553──►  kali (msf + sshd)    │
│   python:3.10 + deps                              kali-rolling + MSF   │
└───────────────────────────────────────────────────────────────────────┘
                                                          │
                                                 scans / exploits
                                                          ▼
                                    ┌──────────────────────────────────┐
                                    │  target VM  (Vagrant / VirtualBox)│
                                    │  Metasploitable 3 — Ubuntu 14.04  │
                                    │  kernel ~3.13  (TARGET_IP)        │
                                    └──────────────────────────────────┘
```

## ⚠️ Why the target is a VM, not a container

Containers share the **host kernel**. The whole privesc kernel path — overlayfs
(CVE-2015-1328) and DirtyCow (CVE-2016-5195) on **kernel 3.13** — targets the
*guest* kernel. A container has no guest kernel to exploit, so root-via-kernel
becomes untestable. MS3 is distributed as a Packer/Vagrant VM for exactly this
reason. **Keep the target a VM.**

---

## Prerequisites

- **Docker + Docker Compose v2** (`docker compose`, not the old `docker-compose`).
- **Vagrant + VirtualBox** (for the target VM).
- An **OpenAI API key**.
- ~8 GB disk (the Kali image with Metasploit is ~2 GB; the MS3 box is several GB).

---

## 1. Configure

```bash
cp .env.example .env
# edit .env: set OPENAI_API_KEY (required). The lab endpoints default sensibly.
```

Every lab value (`KALI_IP`, `TARGET_IP`, creds, `MSF_PORT`, model names) is read
from the environment with the original defaults baked in
(`core_agents/common.py`), so you never edit code to move the lab.

## 2. Bring up the attacker + framework (containers)

```bash
docker compose build          # first build is slow (Metasploit in the Kali image)
docker compose up -d kali     # starts sshd + a FRESH msfrpcd (foreground in-container)
docker compose run --rm app python tests/run_offline.py   # sanity: 8 suites, no lab needed
```

The `app` container reaches Kali by the compose DNS name `kali` (so `KALI_IP=kali`
in `.env`). A fresh `msfrpcd` per `up` is also the lab-hygiene fix — it avoids the
stale-handler wedge that shows up as 120 s-per-command in the logs.

## 3. Build the RAG knowledge base (once)

Needs the API key (uses OpenAI embeddings), so it runs at runtime, not build time.
It persists to the `lgg-db` volume.

```bash
docker compose run --rm app python database_utils/build_database.py
```

> The RAG **source documents** (`database_utils/documents/`) are `.gitignore`d, so
> they are NOT in the repo — supply them before building (Metasploit technique
> PDFs/CSVs/YAML/Markdown). Without them the KB is empty but the pipeline still
> runs (RAG queries just return nothing).

## 4. Bring up the target (VM)

```bash
vagrant up                    # boots Metasploitable 3 at TARGET_IP (default 192.168.34.7)
ssh kali@... 'ping -c2 <TARGET_IP>'   # confirm reachable from the attacker (see Networking)
```

If the box won't download, build MS3 locally from
<https://github.com/rapid7/metasploitable3> (Packer `./build.sh ub1404`), then
`vagrant box add` it and update `Vagrantfile`'s `t.vm.box`.

## 5. Run a scenario

```bash
docker compose run --rm app python experiments/live_test_continuum.py
# logs land in ./logs (bind-mounted)
```

---

## Networking (the part that needs your attention)

The Kali **container** must reach the MS3 **VM**. This is host-OS-specific:

- **Linux host (recommended):** the simplest robust option is to run the `kali`
  service with `network_mode: host` so it shares the host's network stack and can
  reach the VM's host-only/bridged network directly. Trade-off: with host
  networking there's no compose DNS, so set `KALI_IP=127.0.0.1` (or the host IP)
  for the `app` service. Alternatively, put the Vagrant VM on a **bridged
  adapter** on the same LAN as the Docker host and let the container route out
  through the host (works for outbound scans on most Linux setups).
- **macOS / Windows (Docker Desktop):** containers can't directly reach a
  VirtualBox host-only network. Options: (a) bridge the VM onto your physical LAN
  and set `TARGET_IP` to its LAN address; (b) run the **framework directly on the
  host** (`pip install -r requirements.txt`) instead of in a container, and keep
  only Kali+target as before; (c) run everything as VMs (see below).

Whatever you choose, the only thing the code cares about is that `KALI_IP` and
`TARGET_IP` are correct and mutually routable — set them in `.env`.

### Alternative: all-VM lab
If the container↔VM networking is more trouble than it's worth on your host, put
Kali in the Vagrantfile too (multi-machine) and skip Docker entirely — MS3 is
Vagrant-native and this sidesteps all cross-boundary routing. The container files
here still work for the framework itself.

---

## Moving the lab / changing IPs

Set the values in `.env` — nothing in code needs editing:

| Var | Meaning | Default |
|---|---|---|
| `KALI_IP` | attacker (Kali/msfrpcd) address the framework connects to | `kali` (compose DNS) / `192.168.34.6` |
| `TARGET_IP` | Metasploitable 3 target | `192.168.34.7` |
| `KALI_USER`/`KALI_PASS` | SSH + MSF creds | `kali`/`kali` |
| `MSF_PORT`/`MSF_USER`/`MSF_PASS` | msfrpcd | `55553`/`kali`/`kali` |
| `LGG_MODEL`, `LGG_MODEL_INITIAL_ACCESS` | model overrides | `gpt-4o-mini` |

The per-scenario target also lives in each `examples/*_graph.py` / driver; those
default to `192.168.34.7` and accept a `target_ip=` arg — wire them to
`common.TARGET_IP` if you want one knob.

---

## What this does NOT containerize (by design)

- **The target's kernel** — see the warning up top; kernel privesc needs the VM.
- **Real MS3 service versions** — only the VM box has the exact vulnerable
  ProFTPD/UnrealIRCd/etc. builds the graphs target.

For a throwaway CI/demo that doesn't need the kernel path, you could swap the VM
for a vulnerable-service container, but it won't validate privesc — keep the VM
for real work.
