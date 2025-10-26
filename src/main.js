function setupHandlers() {
  const tauri = window.__TAURI__;
  const invoke = tauri?.core?.invoke ?? tauri?.invoke;

  if (typeof invoke !== 'function') {
    console.error('Tauri invoke API not available yet. Retrying...');
    setTimeout(setupHandlers, 100);
    return;
  }

  const ipInput = document.getElementById('tv-ip');
  const pskInput = document.getElementById('tv-psk');

  function loadSettings() {
    try {
      const saved = JSON.parse(localStorage.getItem('sonyTvSettings') || '{}');
      if (saved.ip && ipInput) {
        ipInput.value = saved.ip;
      }
      if (saved.psk && pskInput) {
        pskInput.value = saved.psk;
      }
    } catch (err) {
      console.warn('Failed to load saved settings', err);
    }
  }

  function persistSettings() {
    const data = {
      ip: ipInput?.value?.trim() || '',
      psk: pskInput?.value?.trim() || ''
    };
    localStorage.setItem('sonyTvSettings', JSON.stringify(data));
    return data;
  }

  loadSettings();

  ipInput?.addEventListener('change', persistSettings);
  ipInput?.addEventListener('blur', persistSettings);
  pskInput?.addEventListener('change', persistSettings);
  pskInput?.addEventListener('blur', persistSettings);

  async function send(code) {
    const { ip, psk } = persistSettings();
    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }
    try {
      const result = await invoke('send_ircc', { ip, code, psk: psk || null });
      console.log(result);
      alert(result);
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
      const { psk } = persistSettings();
      const result = await invoke('scan_network', { psk: psk || null });
      if (logDiv) {
        logDiv.innerHTML = result.logs.map(log => `<p>${log}</p>`).join('');
      }

      if (result.ips.length > 0) {
        if (ipInput) {
          ipInput.value = result.ips[0];
        }
        persistSettings();
        alert(`Found ${result.ips.length} possible TV(s): ${result.ips.join(', ')}\nUsing: ${result.ips[0]}`);
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