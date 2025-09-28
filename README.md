# Task-4-Setup-and-Use-a-Firewall-on-Windows-Linux
**Objective**:-Configure and test basic firewall rules to allow or block traffic.

## Windows Firewall Configuration Steps

### 1. Enable Windows Defender Firewall
- Open **Windows Security** → **Firewall & network protection**
- Ensure firewall is **ON** for all network profiles:
  - Domain network
  - Private network  
  - Public network

### 2. Create Inbound Rule for Python Server
- Open **Windows Defender Firewall with Advanced Security**
- Navigate to **Inbound Rules** → **New Rule**
- Configure rule:
  - **Rule Type**: Port
  - **Protocol**: TCP
  - **Port**: 8000 (for localhost:8000)
  - **Action**: Allow the connection
  - **Profile**: Apply to all profiles
  - **Name**: "Python Firewall Server"

### 3. Block Malicious Traffic Patterns
- Create **Outbound Rules** to block suspicious connections:
  - Block connections to known malicious IPs
  - Restrict unnecessary outbound traffic on non-standard ports

### 4. Application-Specific Rules
- Add rule for **Python.exe**:
  - **Action**: Allow
  - **Direction**: Inbound/Outbound
  - **Scope**: Local subnet only
  - **Purpose**: Enable firewall server operation

## Testing the Configuration

### 1. Start the Firewall Server
```powershell
python firewall_server.py
```

### 2. Test Legitimate Traffic
```powershell
curl http://localhost:8000/
# Expected: 200 OK response
```

### 3. Test Blocked Traffic
```powershell
curl http://localhost:8000/tomcatwar.jsp
# Expected: 403 Forbidden response
```

### 4. Test Malicious Headers
```powersehll
curl -H "c1: Runtime" -H "c2: <%" -H "suffix: %>//" http://localhost:8000/
# Expected: 403 Forbidden response
```

## Troubleshooting

**Server won't start:**
- Check if port 8000 is available: `netstat -an | findstr 8000`
- Verify firewall rule allows Python.exe

**Can't access server:**
- Confirm inbound rule for port 8000 is enabled
- Test with `telnet localhost 8000`

**False positives:**
- Review detection thresholds in `Firewall_Config.py`
- Adjust header matching criteria as needed

