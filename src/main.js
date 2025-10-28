console.log('main.js loaded');

function setupHandlers() {
  const tauri = window.__TAURI__;
  let invokeFn;
  if (tauri && tauri.core && typeof tauri.core.invoke === 'function') {
    invokeFn = tauri.core.invoke;
  } else if (tauri && typeof tauri.invoke === 'function') {
    invokeFn = tauri.invoke;
  }

  if (typeof invokeFn !== 'function') {
    console.error('Tauri invoke API not available yet. Retrying...');
    setTimeout(setupHandlers, 100);
    return;
  }

  const ipInput = document.getElementById('tv-ip');
  const pskInput = document.getElementById('tv-psk');
  const pinInput = document.getElementById('tv-pin');
  const pairingStatusInput = document.getElementById('pairing-status');
  const pairingLogArea = document.getElementById('pairing-log');

  function loadSettings() {
    try {
      const saved = JSON.parse(localStorage.getItem('sonyTvSettings') || '{}');
      if (saved.ip && ipInput) {
        ipInput.value = saved.ip;
      }
      if (saved.psk && pskInput) {
        pskInput.value = saved.psk;
      }
      if (saved.pin && pinInput) {
        pinInput.value = saved.pin;
      }
    } catch (err) {
      console.warn('Failed to load saved settings', err);
    }
  }

  function persistSettings() {
    const data = {
      ip: ipInput && ipInput.value ? ipInput.value.trim() : '',
      psk: pskInput && pskInput.value ? pskInput.value.trim() : '',
      pin: pinInput && pinInput.value ? pinInput.value.trim() : ''
    };
    localStorage.setItem('sonyTvSettings', JSON.stringify(data));
    return data;
  }

  function loadPairingState() {
    try {
      return JSON.parse(localStorage.getItem('sonyTvPairing') || '{}');
    } catch (err) {
      console.warn('Failed to load pairing state', err);
      return {};
    }
  }

  function savePairingState(state) {
    localStorage.setItem('sonyTvPairing', JSON.stringify(state));
  }

  function setPairingStatus(message) {
    if (pairingStatusInput) {
      pairingStatusInput.value = message;
    }
  }

  function appendPairingLog(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const formatted = `[${timestamp}] ${message}`;

    if (level === 'error') {
      console.error(formatted);
    } else if (level === 'warn') {
      console.warn(formatted);
    } else {
      console.log(formatted);
    }

    if (pairingLogArea) {
      if (pairingLogArea.value === '' || pairingLogArea.value === 'Pairing logs will appear here...') {
        pairingLogArea.value = formatted;
      } else {
        pairingLogArea.value += `\n${formatted}`;
      }
      pairingLogArea.scrollTop = pairingLogArea.scrollHeight;
    }
  }

  function restorePairingStatus() {
    const state = loadPairingState();
    if (!pairingStatusInput) {
      return;
    }

    if (state.clientId) {
      const text = state.userId
        ? `Client ID: ${state.clientId} | User ID: ${state.userId}`
        : `Client ID: ${state.clientId}`;
      pairingStatusInput.value = text;
    }
  }

  loadSettings();
  restorePairingStatus();

  if (ipInput) {
    ipInput.addEventListener('change', persistSettings);
    ipInput.addEventListener('blur', persistSettings);
  }
  if (pskInput) {
    pskInput.addEventListener('change', persistSettings);
    pskInput.addEventListener('blur', persistSettings);
  }
  if (pinInput) {
    pinInput.addEventListener('change', persistSettings);
    pinInput.addEventListener('blur', persistSettings);
  }

  async function send(code) {
    const { ip, psk, pin } = persistSettings();
    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }
    try {
  const result = await invokeFn('send_ircc', { ip, code, psk: psk || null, pin: pin || null });
      console.log(result);
      alert(result);
    } catch (err) {
      console.error(err);
      alert('Error: ' + err);
    }
  }

  async function castLaunchApp(appName) {
    const { ip } = persistSettings();
    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }
    try {
      const result = await invokeFn('cast_launch_app', { ip, appName });
      console.log(result);
      alert(result);
    } catch (err) {
      console.error(err);
      alert('Error: ' + err);
    }
  }

  function populateTab(tabId, devices) {
    const tabContent = document.getElementById(tabId);
    if (!tabContent) return;

    if (!devices || devices.length === 0) {
      tabContent.innerHTML = '<p>No devices found.</p>';
      return;
    }

    const table = document.createElement('table');
    table.innerHTML = `
      <thead>
        <tr>
          <th>IP</th>
          <th>Name</th>
          <th>Service</th>
          <th>Status</th>
          <th>MAC</th>
          <th>Vendor</th>
          <th>Open Ports</th>
        </tr>
      </thead>
      <tbody>
        ${devices.map(dev => {
          const portDisplay = Array.isArray(dev.ports)
            ? (dev.ports.length > 0 ? dev.ports.join(', ') : 'None')
            : 'N/A';
          return `
          <tr>
            <td>${dev.ip}</td>
            <td>${dev.name || 'N/A'}</td>
            <td>${dev.service || 'N/A'}</td>
            <td>${dev.status}</td>
            <td>${dev.mac || 'N/A'}</td>
            <td>${dev.vendor || 'N/A'}</td>
            <td>${portDisplay}</td>
          </tr>
        `;
        }).join('')}
      </tbody>
    `;
    tabContent.innerHTML = '';
    tabContent.appendChild(table);
  }

  function populateRawMdnsTab(tabId, records) {
    const tabContent = document.getElementById(tabId);
    if (!tabContent) return;

    if (!records || records.length === 0) {
      tabContent.innerHTML = '<p>No mDNS records captured.</p>';
      return;
    }

    const table = document.createElement('table');
    table.innerHTML = `
      <thead>
        <tr>
          <th>Service</th>
          <th>Full Name</th>
          <th>Hostname</th>
          <th>Port</th>
          <th>IPs</th>
          <th>TXT</th>
        </tr>
      </thead>
      <tbody>
        ${records.map(rec => `
          <tr>
            <td>${rec.service}</td>
            <td>${rec.fullname}</td>
            <td>${rec.hostname || 'N/A'}</td>
            <td>${rec.port ?? 'N/A'}</td>
            <td>${(rec.ips || []).join(', ') || 'N/A'}</td>
            <td>${(rec.txt || []).join('; ') || 'N/A'}</td>
          </tr>
        `).join('')}
      </tbody>
    `;
    tabContent.innerHTML = '';
    tabContent.appendChild(table);
  }

  window.showTab = function(tabName, buttonEl) {
    const tabs = document.querySelectorAll('.tab-content');
    const buttons = document.querySelectorAll('.tab-btn');
    tabs.forEach(tab => tab.classList.remove('active'));
    buttons.forEach(btn => btn.classList.remove('active'));
    const activeTab = document.getElementById(`${tabName}-tab`);
    if (activeTab) {
      activeTab.classList.add('active');
    }
    if (buttonEl) {
      buttonEl.classList.add('active');
    }
  };

  async function scanNetwork() {
    console.log('Starting scan...');
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
      const { psk, pin } = persistSettings();
      console.log('Invoking scan_network');
  const result = await invokeFn('scan_network', { psk: psk || null, pin: pin || null });
      console.log('Result:', result);
      if (logDiv) {
        logDiv.innerHTML = (result.logs || []).map(log => `<p>${log}</p>`).join('');
      }

      // Populate tabs
      populateTab('mdns-tab', result.mdns_devices || []);
  populateRawMdnsTab('mdns-raw-tab', result.mdns_raw_records || []);
      populateTab('ssdp-tab', result.ssdp_devices || []);
      populateTab('arp-tab', result.arp_devices || []);

      if ((result.sony_tvs || []).length > 0) {
        if (ipInput) {
          ipInput.value = result.sony_tvs[0];
        }
        persistSettings();
        alert(`Found ${result.sony_tvs.length} Sony TV(s): ${result.sony_tvs.join(', ')}\nUsing: ${result.sony_tvs[0]}`);
      } else {
        alert('No Sony TVs found on the network. Check the tabs for discovered devices.');
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

  async function testConnection() {
    const { ip } = persistSettings();
    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }
    try {
      const result = await invokeFn('test_connection', { ip });
      console.log(result);
      alert(result);
    } catch (err) {
      console.error(err);
      alert('Error: ' + err);
    }
  }
  async function startPairing() {
    console.log('startPairing function called');
    alert('Starting pairing...');
    const { ip } = persistSettings();
    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }

    try {
      appendPairingLog(`[startPairing] Initiating pairing request for IP: ${ip}`);
      if (!invokeFn) {
        appendPairingLog('[startPairing] invokeFn is undefined – Tauri might not be ready yet.', 'warn');
      }
      const startedAt = Date.now();
      const result = await invokeFn('start_pairing', { ip });
      appendPairingLog(`[startPairing] Pairing command completed in ${Date.now() - startedAt} ms`);
      appendPairingLog(`[startPairing] Response: ${JSON.stringify(result)}`);

      const statusText = `Client ID: ${result.client_id} (${result.transport})`;
      setPairingStatus(statusText);

      const state = loadPairingState();
      state.clientId = result.client_id;
      state.transport = result.transport;
      delete state.userId;
      savePairingState(state);

      alert(result.message);
    } catch (err) {
      appendPairingLog(`[startPairing] Failed with error: ${err}`, 'error');
      console.error(err);
      alert('Error starting pairing: ' + err);
    }
  }

  async function completePairing() {
    const { ip } = persistSettings();
    const pinField = document.getElementById('pairing-pin');
    const pinValue = pinField && pinField.value ? pinField.value.trim() : '';

    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }
    if (!pinValue) {
      alert('Enter the PIN displayed on the TV.');
      return;
    }

    try {
  appendPairingLog(`[completePairing] Submitting PIN for IP: ${ip}`);
      const startedAt = Date.now();
      const result = await invokeFn('complete_pairing', { ip, pin: pinValue });
  appendPairingLog(`[completePairing] Completed in ${Date.now() - startedAt} ms`);
  appendPairingLog(`[completePairing] Response: ${JSON.stringify(result)}`);

      const statusText = result.user_id
        ? `Client ID: ${result.client_id} | User ID: ${result.user_id}`
        : `Client ID: ${result.client_id}`;
      setPairingStatus(statusText);

      const state = loadPairingState();
      state.clientId = result.client_id;
      state.transport = result.transport;
      if (result.user_id) {
        state.userId = result.user_id;
      }
      savePairingState(state);

      if (pinField) {
        pinField.value = '';
      }

      alert(result.message);
    } catch (err) {
      appendPairingLog(`[completePairing] Failed with error: ${err}`, 'error');
      console.error(err);
      alert('Error completing pairing: ' + err);
    }
  }

  async function sendRemoteKey(keyCode) {
    const ip = document.getElementById('tv-ip').value.trim();
    if (!ip) {
      alert('Please enter the TV IP address first.');
      return;
    }

    try {
      const result = await window.__TAURI__.core.invoke('send_remote_key', { ip, keyCode });
      console.log(`[sendRemoteKey] Sent ${keyCode} to ${ip}:`, result);
    } catch (err) {
      console.error(`[sendRemoteKey] Error sending ${keyCode}:`, err);
      alert(`Error sending remote key: ${err}`);
    }
  }

  window.send = send;
  window.scanNetwork = scanNetwork;
  window.castLaunchApp = castLaunchApp;
  window.testConnection = testConnection;
  window.launchCustomApp = launchCustomApp;
  window.startPairing = startPairing;
  window.completePairing = completePairing;
  window.sendRemoteKey = sendRemoteKey;
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

if (typeof window.startPairing !== 'function') {
  window.startPairing = () => {
    alert('Pairing requires the Tauri runtime. Launch the desktop app to use this feature.');
  };
}

if (typeof window.completePairing !== 'function') {
  window.completePairing = () => {
    alert('Pairing requires the Tauri runtime. Launch the desktop app to use this feature.');
  };
}

if (typeof window.sendRemoteKey !== 'function') {
  window.sendRemoteKey = () => {
    alert('Remote key commands require the Tauri runtime and IRCC configuration. Launch the desktop app to try again.');
  };
}

if (typeof window.launchCustomApp !== 'function') {
  window.launchCustomApp = () => {
    alert('Custom app launching requires the Tauri runtime. Launch the desktop app and try again.');
  };
}