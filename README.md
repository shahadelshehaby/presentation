# CodeGuard – Code Security Scanner (port 5200)

CodeGuard reads every file of your platforms (Camera Health, NVR Clips, Gantry Watch, FDD Evaluation,
Root Cause, Engineering City …) line by line, and reports security weaknesses, leaked passwords, risky
libraries, bugs, and signs of malware or tampering. Your OT security engineer reviews each finding and
records a remark and a decision. The optional AI reviewer (Phase 2) explains findings in plain English and
proposes fixes, which are applied only after an engineer approves them.

Everything runs offline on this PC. CodeGuard never runs the code it scans, and the AI can only read code
and suggest text.

---

## 1. Start

1. Unzip into its own folder, e.g. `D:\Platforms\codeguard`.
2. Double-click **`run.bat`**. The page opens at **http://127.0.0.1:5200**.
   CodeGuard only needs Flask, which your other platforms already use. If Flask is missing,
   `run.bat` installs it from `usb_bundle\wheels` (see section 6).

## 2. First-time setup (5 minutes)

1. **Settings → People.** Add your OT security engineer and anyone else who will record remarks.
   Then pick your name at the top right of the page.
2. **Settings → Approval PIN.** Set a PIN. It is needed to mark false positives or accepted risks,
   apply or undo fixes, approve baselines, remove platforms and change settings.
3. **Platforms → Connect platform folders.** Browse to the folder that holds your platforms
   (e.g. `D:\Platforms`), click **Find platforms inside**, tick the ones you want and click **Add selected**.
   Names are read from each platform's `building_status.py`. You can also add a single folder
   with **Add this folder**.
4. **Settings → Self-test.** Click **Run self-test**. It scans a deliberately unsafe sample and confirms
   that all 37 checks fire.
5. **Settings → Vulnerability database.** Import `PyPI_all.zip` from the USB bundle (section 6).

The first scan of each platform records its **baseline** (the approved state of every file).

## 3. Add it to Engineering City

In Engineering City: **Settings → Buildings → add a building** named e.g. "Security". Then add a floor to it
with the program address **`http://127.0.0.1:5200/`** and click **Test** next to "Status page".
It should say *Found: CodeGuard - Code Security Scanner*.

- **What counts as an item:** one file scanned. Issues are new findings.
- **Team roles:** listed in `TEAM` at the top of `building_status.py`, with the minutes a person would need
  per file. Correct them for your site, or override them in the city's Team table.

## 4. What it checks (6 layers)

| Layer | Examples | Rules |
|---|---|---|
| Security rules | shell commands built from web input, `debug=True`, network-exposed app without login, SQL built from text, file paths from the browser, uploads saved under the browser's file name, `verify=False`, missing timeouts, unsafe `eval`/`pickle`/`yaml.load`, web pages building HTML from data, scripts loaded from the internet | PY001–PY020, JS001–JS006 |
| Secrets | `rtsp://admin:pass@…`, passwords/tokens in code or settings files, private keys, cloud tokens | SEC001–SEC005 |
| Libraries | known vulnerabilities (offline OSV database), unpinned versions, `pip install` from the internet | DEP001–DEP002, BAT001 |
| Bugs & quality | syntax errors, undefined names, **two pages on the same address**, **functions defined twice** (common after merging updates), silent `except: pass`, `open()` without `encoding=` (breaks Arabic text on Windows), dead code | BUG001–BUG010 |
| Malware & tampering | hidden encoded code, reverse-shell patterns, `report.pdf.exe`, unexpected programs, PowerShell bypass/download, start-up changes, **any file changed since the approved baseline** | MAL001–MAL005, BAT002–BAT004, TAMP001–TAMP003 |
| AI reviewer | problems the fixed rules cannot see (Phase 2) | AI001 |

Every finding explains **why it matters** and **how to fix it** in plain English.
Passwords are always masked (`Ha****`) on screen, in reports, in exports and in what is sent to the AI.
They are never stored.

To silence one line on purpose, add the comment `# codeguard: ignore - <reason>`
(in .bat files: `& rem codeguard: ignore - <reason>`). Prefer the **False positive** decision instead,
because it records who decided and why.

## 5. The engineer's workflow

Open **Findings**. Each finding moves through these statuses:

- **New** – just found; nobody has looked yet.
- **Under review** – being checked (set automatically when someone adds a remark).
- **Confirmed** – a real problem; the fix is planned.
- **False positive** – not a real problem here. Needs a reason and the PIN.
- **Accepted risk** – real, but accepted for now (e.g. "PC is isolated, fix in Q1"). Needs a reason and the
  PIN, and can have a **review-by date**; when that date passes, it reopens automatically.
- **Fixed** – set automatically when a scan no longer finds it.

Every status change and remark is kept in the finding's **History** with name, role and time.
If a fixed problem comes back, it reopens with a note. You can select many findings and update them at once.

**Score and grade per platform:** only New, Under review and Confirmed findings count. Grades run A
(≥90) to F; any open critical caps the grade at D.

**Tampering:** after you install an update to a platform, its changed files appear as
*"File changed since the approved baseline"*. If the change is yours, click **Platforms → Approve current files
as baseline**. Fixes applied through CodeGuard update the baseline automatically.

**Schedule:** every platform is scanned each night (default 02:30; change it in Settings), plus whenever
you click **Scan now** or **Scan all**.

**Reports:** **Reports** opens a printable report (use *Print / Save as PDF*), and there is a CSV export
for Excel. **Libraries** shows every package with its version and known vulnerabilities, and you can
download each platform's **SBOM** (CycloneDX format, which auditors increasingly ask for).

## 6. Offline install and updates (USB)

On a PC **with internet**:

1. Copy the CodeGuard folder there.
2. Edit `tools\prepare_usb_bundle.bat`: set `PYVER` to the OT PC's Python version (`python --version`).
3. Run it. It creates `usb_bundle\` containing:
   - Flask and Bandit wheels.
   - The OSV vulnerability database, `vulndb\PyPI_all.zip`.
   - A SHA-256 checksum for every file.

On the **offline OT PC**:

4. Copy `usb_bundle` into the CodeGuard folder.
5. Run `tools\install_from_usb.bat`. It checks every checksum first and **refuses to install anything that
   doesn't match**. Then it installs from the bundle without internet and imports the database.

To refresh the vulnerability database later, repeat steps 1–5 (monthly is a good rhythm). You can also import
only the zip from **Settings → Vulnerability database**.

**Optional extra tools.** CodeGuard uses these automatically when they are found; their findings are tagged
with the tool's name.

- **Bandit:** included in the bundle.
- **Gitleaks:** download `gitleaks.exe` from its GitHub releases page on the internet PC, copy it over, and set
  its path in Settings.
- **ClamAV:** install it on the internet PC and run `freshclam` there. Copy the program and its database folder
  over, then set the `clamscan.exe` path in Settings.
- **Semgrep:** needs a local rules folder. It never downloads rules.

## 7. Phase 2 – the AI reviewer (local model, no internet)

The AI reviewer works with any local server that speaks the OpenAI-compatible chat API: Ollama, llama.cpp
(`llama-server`), LM Studio or vLLM. The simplest route is Ollama.

On the **internet PC**:

1. Install Ollama.
2. Run `ollama pull gpt-oss:20b`. Any model with good tool/JSON skills works; `gpt-oss:20b` needs about 16 GB
   of memory, and bigger models give better answers.
3. Copy the Ollama installer and the models folder (`%USERPROFILE%\.ollama\models`) to the USB stick.

On the **AI PC**:

4. Install Ollama and copy the models folder to the same place.
5. Run `ollama list` to see the exact model name.
6. Keep Ollama on its default address, `127.0.0.1`. Do **not** set `OLLAMA_HOST=0.0.0.0`: an
   unauthenticated model server on the network can be abused.

In CodeGuard, go to **Settings → AI reviewer**:

7. Switch it on, enter `http://127.0.0.1:11434/v1` and the model name, then click **Save settings** and
   **Test connection**.

What the AI does:

- **Explain this finding.** It gives a verdict (likely real, likely false positive or unsure) with confidence,
  a plain explanation, the impact on this platform and how to fix it. The result is saved as an
  "AI reviewer" remark. The engineer still decides.
- **Propose a fix.** It shows a before/after diff that the engineer can edit, then **Approve and apply**
  (with the PIN) or **Reject**. Before writing, CodeGuard:
  - checks that the file hasn't changed since the fix was proposed;
  - checks that the result still compiles;
  - keeps a backup in `codeguard_data\backups\`.

  It then re-scans. **Undo** restores the backup.
- **Review a whole file** (AI reviewer tab). It finds problems the rules cannot see. These are marked
  **AI only – needs review**.
- **Auto-triage** (optional). After every scan, it explains the new high and critical findings.

AI answers can be wrong. That is why every AI result is a suggestion with a human decision recorded next to it.

## 8. CodeGuard's own safety

- It listens on `127.0.0.1` only, so only this PC can open it. If you change this in Settings, set the PIN and
  allow port 5200 in Windows Firewall only for the PCs that need it.
- It reads platform files, and writes to them only when an approved fix is applied, always with a backup.
- Scanned files can never make it run code: files are parsed, never executed.
- The AI receives code with passwords masked. Instructions written inside scanned code are treated as data.
- CodeGuard scans itself too. Add its own folder as a platform.

## 9. Files

| File | Purpose |
|---|---|
| `app.py` | web pages and API |
| `engine.py` | runs scans, tracks findings, baseline, score, nightly schedule |
| `scan_python.py` | Python checks (reads code structure, not just text) |
| `scan_text.py` | web page, script, secrets and malware checks |
| `deps.py` | libraries, vulnerability database, SBOM |
| `external.py` | optional Bandit / Semgrep / Gitleaks / ClamAV |
| `ai.py` | AI reviewer: explain, propose / apply / undo fixes, file review |
| `rules.py` | all rules with plain-English explanations |
| `db.py` | storage (`codeguard_data\codeguard.db`, `settings.json`) |
| `building_status.py` | Engineering City status page |
| `selftest_sample\` | deliberately unsafe sample for the self-test. **Never run it.** |
| `tools\` | USB bundle preparation, verified install, database import |

**Back up** the `codeguard_data` folder. It holds all findings, remarks and decisions.
