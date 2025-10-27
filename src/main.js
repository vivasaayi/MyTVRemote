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

  loadSettings();

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
    const { ip, psk } = persistSettings();
    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }
    try {
      const result = await invokeFn('cast_launch_app', { ip, appName, psk: psk || null });
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
  async function launchCustomApp() {
    const appName = document.getElementById('custom-app').value.trim();
    if (!appName) {
      alert('Enter an app ID first.');
      return;
    }
    const { ip, psk } = persistSettings();
    if (!ip) {
      alert('Enter the TV IP address first.');
      return;
    }
    try {
      const result = await invokeFn('cast_launch_app', { ip, appName, psk: psk || null });
      console.log(result);
      alert(result);
    } catch (err) {
      console.error(err);
      alert('Error: ' + err);
    }
  }

  window.send = send;
  window.scanNetwork = scanNetwork;
  window.castLaunchApp = castLaunchApp;
  window.testConnection = testConnection;
  window.launchCustomApp = launchCustomApp;
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