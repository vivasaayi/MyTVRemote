function setupHandlers() {
  const tauri = window.__TAURI__;
  const invoke = tauri?.core?.invoke ?? tauri?.invoke;

  if (typeof invoke !== 'function') {
    console.error('Tauri invoke API not available yet.');
    const logDiv = document.getElementById('scan-log');
    if (logDiv) {
      logDiv.innerHTML = '<p style="color:red;">Tauri API not ready. Please restart the app.</p>';
      logDiv.style.display = 'block';
    }
    return;
  }

  async function send(code) {
    const ip = document.getElementById('tv-ip').value;
    try {
      const result = await invoke('send_ircc', { ip, code });
      console.log(result);
      alert('Command sent!');
    } catch (err) {
      console.error(err);
      alert('Error: ' + err);
    }
  }

  async function scanNetwork() {
    const button = document.getElementById('scan-btn');
    const logDiv = document.getElementById('scan-log');
    const originalText = button.textContent;
    
    button.textContent = 'Scanning...';
    button.disabled = true;
    if (logDiv) {
      logDiv.innerHTML = '<p>Starting scan...</p>';
      logDiv.style.display = 'block';
    }
    
    try {
      const result = await invoke('scan_network');
      if (logDiv) {
        logDiv.innerHTML = result.logs.map(log => `<p>${log}</p>`).join('');
      }
      
      if (result.ips.length > 0) {
        document.getElementById('tv-ip').value = result.ips[0];
        alert(`Found ${result.ips.length} TV(s): ${result.ips.join(', ')}\nSet to: ${result.ips[0]}`);
      } else {
        alert('No Sony TVs found on the network. Make sure your TV is on and connected to the same network.');
      }
    } catch (err) {
      console.error(err);
      if (logDiv) {
        logDiv.innerHTML = `<p style="color: red;">Error: ${err}</p>`;
      }
      alert('Error scanning network: ' + err);
    } finally {
      button.textContent = originalText;
      button.disabled = false;
    }
  }

  window.send = send;
  window.scanNetwork = scanNetwork;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    if ('__TAURI__' in window) {
      setupHandlers();
    } else {
      window.addEventListener('tauri://ready', setupHandlers, { once: true });
    }
  });
} else {
  if ('__TAURI__' in window) {
    setupHandlers();
  } else {
    window.addEventListener('tauri://ready', setupHandlers, { once: true });
  }
}