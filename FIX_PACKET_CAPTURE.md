# Fixing Packet Capture Issues

## Current Status
- ✅ Scapy updated from 2.5.0 to 2.6.1
- ✅ Cryptography warnings suppressed
- ✅ Network interface detection fixed (now correctly uses `enp0s1`)
- ✅ All location functionality removed from the project
- ⚠️ Packet capture requires sudo privileges

## The Issue
The passive traffic capture shows 0 packets because it requires root/sudo privileges to access raw network sockets.

## Solutions

### Option 1: Run with Sudo (Immediate Fix)
```bash
sudo python3 mapper.py
```

### Option 2: Configure Passwordless Sudo (Production)
Add to `/etc/sudoers` using `sudo visudo`:
```
your_username ALL=(ALL) NOPASSWD: /usr/bin/python3 /home/connorboetig/v2/utils/traffic_capture_sudo.py
```

### Option 3: Test Packet Capture Directly
Test if packet capture works on your system:
```bash
# Test with tcpdump
sudo tcpdump -i enp0s1 -c 10

# Test with python/scapy
sudo python3 -c "from scapy.all import sniff; pkts = sniff(iface='enp0s1', count=5); print(f'Captured {len(pkts)} packets')"
```

## What Was Fixed

1. **Scapy Compatibility**: Updated to Scapy 2.6.1 which has better compatibility with newer cryptography versions

2. **Warning Suppression**: Added `warnings.filterwarnings("ignore")` to prevent cryptography deprecation warnings from interfering

3. **Interface Detection**: Fixed auto-detection to properly identify `enp0s1` instead of looking for `ens01`

4. **Error Handling**: Improved error handling to distinguish between real errors and warnings

## Verification Steps

1. Ensure sudo access:
   ```bash
   sudo echo "Sudo access verified"
   ```

2. Run a scan with passive analysis:
   ```bash
   sudo python3 mapper.py
   # Select a scan type with passive traffic analysis
   ```

3. Generate some network traffic during the capture:
   ```bash
   # In another terminal:
   ping 8.8.8.8
   curl https://example.com
   ```

## Expected Result
With proper sudo privileges, you should see:
- "Passive analysis: 30s elapsed, X devices, Y flows" (where X and Y are > 0)
- Successful capture of network traffic
- Enhanced device discovery through passive monitoring

## Note
The cryptography deprecation warning is now just a warning and doesn't affect functionality. It will be fully resolved when Scapy releases an update for cryptography 48.0.0+ compatibility.