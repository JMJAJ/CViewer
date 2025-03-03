const API_ENDPOINTS = {
    IP_INFO: 'http://ip-api.com/json/',
    IP_INFO_FIELDS: 'status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query',
    PASTEBIN: 'https://pastebin.com/raw/UuJZFNxF',
    CORS_PROXY: 'https://serverless-api-jnzf.vercel.app/api/proxy',
    ASN_INFO: 'https://ipinfo.io/'  
};

let globalState = {
    latitude: null,
    longitude: null,
    asn: null,
    cameras: [],
    activeWindows: [],
    resizeObservers: {},
    advancedMode: false,
    rawData: {
        ipInfo: {},
        asnInfo: {}
    },
    consoleLog: []
};

const DOM = {
    cameraList: document.getElementById('cameraList'),
    addIpForm: document.getElementById('addIpForm'),
    addIpInput: document.getElementById('addIpInput'),
    addIpButton: document.getElementById('addIpButton'),
    sidebar: document.getElementById('sidebar'),
    clock: document.getElementById('clock'),
    cameraCount: document.getElementById('cameraCount'),
    advancedModeButton: document.getElementById('advancedModeButton')
};

const originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn,
    info: console.info
};

console.log = function() {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'log',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.log.apply(console, arguments);
};

console.error = function() {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'error',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.error.apply(console, arguments);
};

console.warn = function() {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'warn',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.warn.apply(console, arguments);
};

console.info = function() {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'info',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.info.apply(console, arguments);
};

const extractIpFromUrl = (url) => {
    const match = url.match(/(\d+\.\d+\.\d+\.\d+)/);
    return match ? match[0] : null;
};

const createElementWithClass = (tag, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    return element;
};

const createElementWithHTML = (tag, html, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.innerHTML = html;
    return element;
};

async function fetchJson(url) {
    try {
        console.log(`Fetching JSON from: ${url}`);
        const response = await fetch(url);
        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorMessage}`);
        }
        return response.json();
    } catch (error) {
        console.error('Error fetching JSON:', error);
        throw error; 
    }
}

const updateCameraCount = () => {
    const count = globalState.cameras.length;
    DOM.cameraCount.textContent = `${count} camera${count !== 1 ? 's' : ''}`;
};

const updateClock = () => {
    const now = new Date();
    DOM.clock.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const removeOverlay = () => {
    const overlay = document.getElementById('overlay');
    if (overlay) {
        overlay.remove();
        console.log('Overlay removed.');
    }
};

const makeDraggable = (windowElement, titlebarElement) => {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
    let isDragging = false;

    if (!titlebarElement || !windowElement) return;

    titlebarElement.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
        if (e.target.closest('button')) return; 

        e = e || window.event;
        e.preventDefault();

        const highestZIndex = Math.max(
            ...Array.from(document.querySelectorAll('.window'))
                .map(w => parseInt(getComputedStyle(w).zIndex) || 0)
        );
        windowElement.style.zIndex = highestZIndex + 1;

        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        document.onmousemove = elementDrag;

        isDragging = true;
        windowElement.classList.add('dragging');
    }

    function elementDrag(e) {
        if (!isDragging) return;

        e = e || window.event;
        e.preventDefault();
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;

        const newTop = windowElement.offsetTop - pos2;
        const newLeft = windowElement.offsetLeft - pos1;

        windowElement.style.top = newTop + "px";
        windowElement.style.left = newLeft + "px";
    }

    function closeDragElement() {
        document.onmouseup = null;
        document.onmousemove = null;
        isDragging = false;
        windowElement.classList.remove('dragging');
    }
};

const setupWindowControls = (windowElement) => {
    if (!windowElement) return;

    const minimizeBtn = windowElement.querySelector('.minimize');
    if (minimizeBtn) {
        minimizeBtn.addEventListener('click', () => {
            const content = windowElement.querySelector('.window-content');
            if (content) {
                content.classList.toggle('minimized');
            }
        });
    }

    const maxBtn = windowElement.querySelector('.maximize');
    if (maxBtn) {
        maxBtn.addEventListener('click', () => {
            const icon = maxBtn.querySelector('i');
            windowElement.classList.toggle('maximized');

            if (windowElement.classList.contains('maximized')) {

                windowElement.dataset.prevTop = windowElement.style.top;
                windowElement.dataset.prevLeft = windowElement.style.left;
                windowElement.dataset.prevWidth = windowElement.style.width;
                windowElement.dataset.prevHeight = windowElement.style.height;
                windowElement.dataset.prevZIndex = windowElement.style.zIndex;

                icon.classList.remove('fa-expand');
                icon.classList.add('fa-compress');

                windowElement.style.top = '0';
                windowElement.style.left = '0';
                windowElement.style.width = '100%';
                windowElement.style.height = '100%';

                const highestZIndex = Math.max(
                    1000,
                    ...Array.from(document.querySelectorAll('.window'))
                        .map(w => parseInt(getComputedStyle(w).zIndex) || 0)
                ) + 10;
                windowElement.style.zIndex = highestZIndex;
            } else {
                icon.classList.remove('fa-compress');
                icon.classList.add('fa-expand');

                windowElement.style.top = windowElement.dataset.prevTop || '';
                windowElement.style.left = windowElement.dataset.prevLeft || '';
                windowElement.style.width = windowElement.dataset.prevWidth || '';
                windowElement.style.height = windowElement.dataset.prevHeight || '';
                windowElement.style.zIndex = windowElement.dataset.prevZIndex || '';
                windowElement.style.borderRadius = '';
            }
        });
    }

    const closeBtn = windowElement.querySelector('.close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            windowElement.classList.add('closing');
            setTimeout(() => {
                windowElement.remove();

                if (windowElement.id === 'advancedDashboard') {
                    globalState.advancedMode = false;
                    return;
                }

                const windowId = windowElement.dataset.id;
                globalState.activeWindows = globalState.activeWindows.filter(w => w !== windowId);

                if (windowId && globalState.resizeObservers[windowId]) {
                    globalState.resizeObservers[windowId].disconnect();
                    delete globalState.resizeObservers[windowId];
                }

                if (globalState.advancedMode) {
                    updateDashboardContent();
                }
            }, 300);
        });
    }
};

const setupTabs = (windowElement) => {
    if (!windowElement) return;

    const tabButtons = windowElement.querySelectorAll('.tab-button');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {

            windowElement.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            windowElement.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            button.classList.add('active');

            const tabId = button.dataset.tab;
            const tabContent = windowElement.querySelector(`#${tabId}`);
            if (tabContent) {
                tabContent.classList.add('active');
            }
        });
    });
};

const addCamera = (url) => {

    if (globalState.cameras.includes(url)) {
        console.log('Camera already exists in the list');
        return false;
    }

    globalState.cameras.push(url);

    const listItem = createElementWithHTML('li', 
        `<i class="fas fa-video"></i> ${url}`,
        'camera-list-item'
    );

    listItem.addEventListener('click', () => openVideoWindow(url));

    DOM.cameraList.appendChild(listItem);

    updateCameraCount();

    return true;
};

document.getElementById('addIpForm').addEventListener('submit', (event) => {
    event.preventDefault();

    const ipInput = document.getElementById('addIpInput').value.trim();

    const rtspRegex = /^rtsp:\/\/(:\S*)?@?(\d{1,3}\.){3}\d{1,3}:\d{1,5}(\/.*)?$/;
    const mjpgRegex = /^https?:\/\/(:\S*)?@?(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?(\/.*)?$/;

    if (!rtspRegex.test(ipInput) && !mjpgRegex.test(ipInput)) {
        alert('Invalid URL format. Please use a valid RTSP or HTTP stream URL.');
        return;
    }

    if (addCamera(ipInput)) {

        document.getElementById('addIpInput').value = '';
    }
});

const fetchPastebinContent = async (url) => {
    try {
        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url }),
        });

        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

        const data = await response.json();
        return data.contents;
    } catch (error) {
        console.error('Error fetching Pastebin content:', error);
        return '';
    }
};

function showLoadingMessage(isLoading) {
    let loadingElement = document.getElementById('loading-message');

    if (isLoading) {
        if (!loadingElement) {
            loadingElement = document.createElement('div');
            loadingElement.id = 'loading-message';
            loadingElement.className = 'loading-message';
            loadingElement.innerHTML = `<div class="spinner"></div><span>Loading camera list...</span>`;
            document.body.appendChild(loadingElement);
        }
        loadingElement.classList.add('visible');
    } else {
        if (loadingElement) {
            loadingElement.classList.remove('visible');
            if (loadingElement.parentNode) {
                loadingElement.parentNode.removeChild(loadingElement);
            }
        }
    }
}

const updateCameraListFromPastebin = async (pastebinUrl) => {

    showLoadingMessage(true);

    const loadingTimeout = setTimeout(() => {
        showLoadingMessage(false);
    }, 10000); 

    try {
        const plainTextContent = await fetchPastebinContent(pastebinUrl);
        const urls = plainTextContent.split('\n').filter(url => url.trim() !== '');

        DOM.cameraList.innerHTML = '';
        globalState.cameras = [];

        urls.forEach(url => {
            addCamera(url);
        });

        updateCameraCount();
    } catch (error) {
        console.error('Error updating camera list:', error);
    } finally {

        clearTimeout(loadingTimeout);
        showLoadingMessage(false);
    }
};

const isMjpgStream = (url) => {
    return url.toLowerCase().includes('.mjpg') || 
           url.toLowerCase().includes('mjpg/video') || 
           url.toLowerCase().includes('mjpeg') ||
           url.toLowerCase().includes('video.cgi');
};

const formatMjpgUrl = (url) => {
    if (isMjpgStream(url)) {
        return url;
    }

    const baseUrl = url.endsWith('/') ? url.slice(0, -1) : url;
    return `${baseUrl}/mjpg/video.mjpg`;
};

const openVideoWindow = (url) => {

    const windowId = `window-${Date.now()}`;

    const template = document.getElementById('videoWindowTemplate');
    const newWindow = template.content.cloneNode(true).querySelector('.window');

    newWindow.dataset.id = windowId;
    newWindow.dataset.streamUrl = url;

    newWindow.querySelector('.video-title').textContent = url;

    const offset = 20 * (globalState.activeWindows.length % 5);
    newWindow.style.top = `${70 + offset}px`;
    newWindow.style.left = `${350 + offset}px`;

    globalState.activeWindows.push(windowId);

    const videoContainer = newWindow.querySelector('.video-container');

    if (url.startsWith('rtsp://')) {

        document.body.appendChild(newWindow);

        newWindow.style.width = '850px';
        newWindow.style.height = '600px';

        const resolution = "720x420";
        const resolutionBase64 = btoa(resolution);

        const statusResolution = newWindow.querySelector('.stream-resolution');
        if (statusResolution) {
            statusResolution.textContent = resolution;
        }

        videoContainer.innerHTML = `
            <iframe id="videoFrame-${windowId}" class="video-player" frameborder="0" allowfullscreen="1"
                src="https://streamedian.com/embed?w=ZXVwLnN0cmVhbWVkaWFuLmNvbQ==&s=${btoa(url)}&r=${resolutionBase64}" 
                width="100%" height="100%">
            </iframe>
            <div id="faceDetectionOverlay-${windowId}" class="face-detection-overlay"></div>
        `;
    } else if (isMjpgStream(url) || url.startsWith('http')) {

        const mjpgUrl = formatMjpgUrl(url);

        document.body.appendChild(newWindow);

        videoContainer.innerHTML = `
            <div class="mjpg-container">
                <img id="mjpgStream-${windowId}" src="${mjpgUrl}" 
                    onerror="this.onerror=null; this.src='${mjpgUrl}?t=' + new Date().getTime();" 
                    alt="MJPG Stream" />
                <div id="faceDetectionOverlay-${windowId}" class="face-detection-overlay"></div>
            </div>
        `;

        const refreshInterval = setInterval(() => {
            const img = document.getElementById(`mjpgStream-${windowId}`);
            const toggle = document.getElementById('autoRefreshToggle');

            if (img && (!toggle || toggle.checked)) {
                img.src = `${mjpgUrl}?t=${new Date().getTime()}`;
            }

            if (!document.getElementById(`mjpgStream-${windowId}`)) {
                clearInterval(refreshInterval);
            }
        }, 30000);
    } else {

        document.body.appendChild(newWindow);

        videoContainer.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Unsupported video format:<br>${url}</p>
            </div>
        `;
    }

    makeDraggable(newWindow, newWindow.querySelector('.window-titlebar'));

    setupWindowControls(newWindow);

    setupTabs(newWindow);

    makeResizable(newWindow);

    const ip = extractIpFromUrl(url);
    if (ip) {
        fetchIPInfo(ip, newWindow);
    }

    return newWindow;
};

const makeResizable = (windowElement) => {
    if (!windowElement) return;

    const handles = ['se', 'sw', 'ne', 'nw', 'n', 's', 'e', 'w'];

    handles.forEach(direction => {
        const handleClass = `resize-handle resize-${direction}`;
        if (!windowElement.querySelector(`.${handleClass.split(' ')[1]}`)) {
            const handle = document.createElement('div');
            handle.className = handleClass;
            windowElement.appendChild(handle);

            handle.addEventListener('mousedown', (e) => {
                e.preventDefault();
                startResize(e, windowElement, direction);
            });
        }
    });
};

const startResize = (e, windowElement, direction) => {
    e.stopPropagation();

    const startX = e.clientX;
    const startY = e.clientY;
    const startWidth = windowElement.offsetWidth;
    const startHeight = windowElement.offsetHeight;
    const startTop = windowElement.offsetTop;
    const startLeft = windowElement.offsetLeft;

    const minWidth = 320;
    const minHeight = 240;

    const resize = (e) => {

        const highestZIndex = Math.max(
            ...Array.from(document.querySelectorAll('.window'))
                .map(w => parseInt(getComputedStyle(w).zIndex) || 0)
        );
        windowElement.style.zIndex = highestZIndex + 1;

        let newWidth = startWidth;
        let newHeight = startHeight;
        let newTop = startTop;
        let newLeft = startLeft;

        const deltaX = e.clientX - startX;
        const deltaY = e.clientY - startY;

        if (direction.includes('e')) newWidth = Math.max(minWidth, startWidth + deltaX);
        if (direction.includes('s')) newHeight = Math.max(minHeight, startHeight + deltaY);
        if (direction.includes('w')) {
            newWidth = Math.max(minWidth, startWidth - deltaX);
            newLeft = startLeft + startWidth - newWidth;
        }
        if (direction.includes('n')) {
            newHeight = Math.max(minHeight, startHeight - deltaY);
            newTop = startTop + startHeight - newHeight;
        }

        windowElement.style.width = `${newWidth}px`;
        windowElement.style.height = `${newHeight}px`;
        windowElement.style.top = `${newTop}px`;
        windowElement.style.left = `${newLeft}px`;
    };

    const stopResize = () => {
        window.removeEventListener('mousemove', resize);
        window.removeEventListener('mouseup', stopResize);
    };

    window.addEventListener('mousemove', resize);
    window.addEventListener('mouseup', stopResize);
};

async function fetchIPInfo(ip, windowElement) {
    if (!ip || !windowElement) return;

    const infoContainer = windowElement.querySelector('#camera-info');
    if (!infoContainer) return;

    infoContainer.innerHTML = `
        <div class="info-card">
            <h3>Camera Information</h3>
            <div class="loading-spinner">
                <div class="spinner"></div>
                <p>Loading IP information...</p>
            </div>
        </div>
    `;

    const loadingTimeout = setTimeout(() => {
        if (windowElement.contains(infoContainer)) {
            infoContainer.innerHTML = `
                <div class="info-card">
                    <h3>Camera Information</h3>
                    <div class="error-message">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>Loading timed out. Please try again.</p>
                    </div>
                </div>
            `;
        }
    }, 15000); 

    try {

        const ipInfoUrl = `${API_ENDPOINTS.IP_INFO}${ip}?fields=${API_ENDPOINTS.IP_INFO_FIELDS}`;
        console.log(`Fetching IP info using proxy from: ${ipInfoUrl}`);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); 

        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: ipInfoUrl }),
            signal: controller.signal
        });

        clearTimeout(timeoutId); 

        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorMessage}`);
        }

        const proxyResponse = await response.json();

        if (!proxyResponse || !proxyResponse.contents) {
            throw new Error('Invalid response from proxy server');
        }

        const ipData = JSON.parse(proxyResponse.contents);

        if (!ipData || !ipData.query) {
            throw new Error('Invalid IP data structure');
        }

        clearTimeout(loadingTimeout);

        updateIPInfoUI(ipData, windowElement);

        if (ipData.lat && ipData.lon) {
            updateGoogleMaps(ipData.lat, ipData.lon, ipData.district, ipData.city, ipData.regionName, windowElement);
        }

        if (ipData.as) {
            const asnMatch = ipData.as.match(/AS(\d+)/);
            if (asnMatch && asnMatch[1]) {
                fetchAndUpdateASN(ip, asnMatch[1], windowElement);
            }
        }

        if (globalState.advancedMode) {
            updateDashboardContent();
        }
    } catch (error) {
        console.error('Error fetching IP info:', error);

        clearTimeout(loadingTimeout);

        if (windowElement.contains(infoContainer)) {
            infoContainer.innerHTML = `
                <div class="info-card">
                    <h3>Camera Information</h3>
                    <div class="error-message">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>Error fetching IP information: ${error.message}</p>
                    </div>
                </div>
            `;
        }
    }
}

const updateIPInfoUI = (data, windowElement) => {
    if (!data || !windowElement) return;

    const windowId = windowElement.dataset.id;
    const infoContainer = windowElement.querySelector('#camera-info');
    if (!infoContainer) return;

    if (windowId) {
        globalState.rawData.ipInfo[windowId] = data;

        if (globalState.advancedMode) {
            updateDashboardContent();
        }
    }

    infoContainer.innerHTML = `
        <div class="info-card">
            <h3>Camera Information</h3>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">IP Address</span>
                    <span class="info-value">${data.query}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Location</span>
                    <span class="info-value">${data.city || 'Unknown'}, ${data.regionName || ''}, ${data.country || ''}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">ISP</span>
                    <span class="info-value">${data.isp || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Organization</span>
                    <span class="info-value">${data.org || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Timezone</span>
                    <span class="info-value">${data.timezone || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">AS Number</span>
                    <span class="info-value">${data.as || 'Unknown'}</span>
                </div>
            </div>
        </div>
    `;
};

const updateGoogleMaps = (lat, lon, district, city, regionName, windowElement) => {
    if (!lat || !lon || !windowElement) return;

    const mapContainer = windowElement.querySelector('#camera-location');
    if (!mapContainer) return;

    const locationName = [district, city, regionName].filter(Boolean).join(', ');

    mapContainer.innerHTML = `
        <div class="info-card">
            <h3>Camera Location</h3>
            <p class="location-name">${locationName}</p>
            <div class="map-container">
                <iframe 
                    width="100%" 
                    height="250" 
                    frameborder="0" 
                    style="border:0"
                    referrerpolicy="no-referrer-when-downgrade"
                    src="https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;coord=${lat},${lon}&amp;q=1%20${district}%20Street%2C%20${city}%2C%20${regionName}&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed"
                    allowfullscreen>
                </iframe>
            </div>
            <div class="coordinates">
                <span>Latitude: ${lat}</span>
                <span>Longitude: ${lon}</span>
            </div>
        </div>
    `;
};

async function fetchAndUpdateASN(ip, asn, windowElement) {
    if (!ip || !asn || !windowElement) return;

    try {

        const asnUrl = `${API_ENDPOINTS.ASN_INFO}AS${asn}/json`;
        console.log(`Fetching ASN info using proxy from: ${asnUrl}`);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); 

        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: asnUrl }),
            signal: controller.signal
        });

        clearTimeout(timeoutId); 

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const proxyResponse = await response.json();

        if (!proxyResponse || !proxyResponse.contents) {
            throw new Error('Invalid response from proxy server');
        }

        const asnData = JSON.parse(proxyResponse.contents);

        if (asnData) {
            updateASNInfoUI(asnData, windowElement);
        }
    } catch (error) {
        console.error('Error fetching ASN info:', error);

    }
}

const updateASNInfoUI = (asnData, windowElement) => {
    if (!asnData || !windowElement) return;

    const windowId = windowElement.dataset.id;
    const infoContainer = windowElement.querySelector('#camera-info');
    if (!infoContainer) return;

    if (windowId) {
        globalState.rawData.asnInfo[windowId] = asnData;

        if (globalState.advancedMode) {
            updateDashboardContent();
        }
    }

    const infoCard = infoContainer.querySelector('.info-card');
    if (!infoCard) return;

    const asnInfoHTML = `
        <div class="info-divider"></div>
        <h4>Network Information</h4>
        <div class="info-grid">
            <div class="info-item">
                <span class="info-label">Network Name</span>
                <span class="info-value">${asnData.name || 'Unknown'}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Network Range</span>
                <span class="info-value">${asnData.network || 'Unknown'}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Network Country</span>
                <span class="info-value">${asnData.country || 'Unknown'}</span>
            </div>
        </div>
    `;

    infoCard.insertAdjacentHTML('beforeend', asnInfoHTML);
};

const initFaceDetection = async (imageElement, overlayElement) => {
    if (!imageElement || !overlayElement || !window.faceapi) return;

    try {

        await Promise.all([
            faceapi.nets.tinyFaceDetector.loadFromUri('/models'),
            faceapi.nets.faceLandmark68Net.loadFromUri('/models'),
            faceapi.nets.faceRecognitionNet.loadFromUri('/models')
        ]);

        const interval = setInterval(async () => {

            const toggle = document.getElementById('faceDetectionToggle');
            if (!toggle || !toggle.checked) {
                overlayElement.innerHTML = '';
                return;
            }

            if (!document.body.contains(imageElement) || !document.body.contains(overlayElement)) {
                clearInterval(interval);
                return;
            }

            try {

                const detections = await faceapi.detectAllFaces(
                    imageElement, 
                    new faceapi.TinyFaceDetectorOptions()
                );

                overlayElement.innerHTML = '';

                detections.forEach(detection => {
                    const { x, y, width, height } = detection.box;

                    const faceBox = document.createElement('div');
                    faceBox.className = 'face-detection-box';
                    faceBox.style.left = `${x}px`;
                    faceBox.style.top = `${y}px`;
                    faceBox.style.width = `${width}px`;
                    faceBox.style.height = `${height}px`;

                    overlayElement.appendChild(faceBox);
                });
            } catch (error) {
                console.error('Face detection error:', error);
            }
        }, 2000);
    } catch (error) {
        console.error('Error initializing face detection:', error);
    }
};

const openAdvancedDashboard = () => {

    if (document.getElementById('advancedDashboard')) {
        return;
    }

    globalState.advancedMode = true;

    const template = document.getElementById('advancedDashboardTemplate');
    const dashboard = template.content.cloneNode(true).querySelector('.advanced-dashboard');

    const windowWidth = window.innerWidth;
    const windowHeight = window.innerHeight;
    dashboard.style.top = `${(windowHeight - 600) / 2}px`;
    dashboard.style.left = `${(windowWidth - 900) / 2}px`;

    document.body.appendChild(dashboard);
    makeDraggable(dashboard, dashboard.querySelector('.window-titlebar'));

    setupWindowControls(dashboard);

    setupDashboardNavigation(dashboard);

    updateDashboardContent();

    updateAdvancedModeTime();
    setInterval(updateAdvancedModeTime, 1000);
};

const closeAdvancedDashboard = () => {
    const dashboard = document.getElementById('advancedDashboard');
    if (dashboard) {
        dashboard.classList.add('closing');
        setTimeout(() => {
            dashboard.remove();
            globalState.advancedMode = false;
        }, 300);
    }
};

const setupDashboardNavigation = (dashboard) => {
    const navItems = dashboard.querySelectorAll('.nav-item');

    navItems.forEach(item => {
        item.addEventListener('click', () => {

            navItems.forEach(nav => nav.classList.remove('active'));

            item.classList.add('active');

            const sectionId = item.dataset.section;
            const sections = dashboard.querySelectorAll('.dashboard-section');
            sections.forEach(section => section.classList.remove('active'));

            const activeSection = dashboard.querySelector(`#${sectionId}`);
            if (activeSection) {
                activeSection.classList.add('active');
            }
        });
    });
};

const updateDashboardContent = () => {

    updateApiEndpointsSection();

    updateStateSection();

    updateCameraDataSection();
};

const updateApiEndpointsSection = () => {
    const ipInfoEndpoint = document.getElementById('ipInfoEndpoint');
    if (ipInfoEndpoint) {
        ipInfoEndpoint.textContent = `${API_ENDPOINTS.IP_INFO}{ip}?fields=${API_ENDPOINTS.IP_INFO_FIELDS}`;
    }

    const asnInfoEndpoint = document.getElementById('asnInfoEndpoint');
    if (asnInfoEndpoint) {
        asnInfoEndpoint.textContent = `${API_ENDPOINTS.ASN_INFO}{asn}/json`;
    }

    const pastebinEndpoint = document.getElementById('pastebinEndpoint');
    if (pastebinEndpoint) {
        pastebinEndpoint.textContent = API_ENDPOINTS.PASTEBIN;
    }
};

const updateStateSection = () => {
    const stateView = document.getElementById('globalStateView');
    if (stateView) {

        const displayState = { ...globalState };

        if (displayState.consoleLog && displayState.consoleLog.length > 0) {
            displayState.consoleLog = `[Array(${displayState.consoleLog.length} items)]`;
        }

        stateView.textContent = JSON.stringify(displayState, null, 2);
    }
};

const updateCameraDataSection = () => {
    const cameraDataList = document.getElementById('camerasDataList');
    if (!cameraDataList) return;

    cameraDataList.innerHTML = '';

    globalState.activeWindows.forEach(windowId => {
        const windowElement = document.querySelector(`.window[data-id="${windowId}"]`);
        if (!windowElement) return;

        const streamUrl = windowElement.dataset.streamUrl;
        const ipInfo = globalState.rawData.ipInfo[windowId];
        const asnInfo = globalState.rawData.asnInfo[windowId];

        const card = document.createElement('div');
        card.className = 'camera-data-card';

        let cardContent = `
            <div class="camera-data-header">
                <i class="fas fa-video"></i>
                <h4>${streamUrl || 'Unknown URL'}</h4>
            </div>
            <div class="camera-data-content">
        `;

        if (ipInfo) {
            cardContent += `
                <div class="data-pair">
                    <span class="data-label">IP:</span>
                    <span class="data-value">${ipInfo.query || 'Unknown'}</span>
                </div>
                <div class="data-pair">
                    <span class="data-label">Location:</span>
                    <span class="data-value">${ipInfo.city || 'Unknown'}, ${ipInfo.country || ''}</span>
                </div>
                <div class="data-pair">
                    <span class="data-label">ASN:</span>
                    <span class="data-value">${ipInfo.as || 'Unknown'}</span>
                </div>
            `;
        } else {
            cardContent += `<p>No IP data available</p>`;
        }

        cardContent += '</div>';
        card.innerHTML = cardContent;
        cameraDataList.appendChild(card);
    });

    if (globalState.activeWindows.length === 0) {
        cameraDataList.innerHTML = '<p>No active cameras to display</p>';
    }
};

const updateConsoleOutput = () => {
    const consoleOutput = document.getElementById('consoleOutput');
    if (!consoleOutput) return;

    consoleOutput.innerHTML = '';

    const lastEntries = globalState.consoleLog.slice(-50);

    lastEntries.forEach(entry => {
        const line = document.createElement('div');
        line.className = 'console-line';

        const time = document.createElement('span');
        time.className = 'console-time';
        time.textContent = `[${entry.time.toLocaleTimeString()}]`;

        const type = document.createElement('span');
        type.className = `console-type ${entry.type}`;
        type.textContent = entry.type.toUpperCase();

        const message = document.createElement('span');
        message.className = 'console-message';
        message.textContent = entry.message;

        line.appendChild(time);
        line.appendChild(type);
        line.appendChild(message);

        consoleOutput.appendChild(line);
    });

    consoleOutput.scrollTop = consoleOutput.scrollHeight;
};

const updateAdvancedModeTime = () => {
    const timeElement = document.getElementById('advancedModeTime');
    if (timeElement) {
        const now = new Date();
        timeElement.textContent = now.toLocaleTimeString();
    }
};

const init = () => {

    makeDraggable(DOM.sidebar, DOM.sidebar.querySelector('.window-titlebar'));

    setupWindowControls(DOM.sidebar);

    updateCameraCount();

    updateClock();
    setInterval(updateClock, 60000);

    updateCameraListFromPastebin(API_ENDPOINTS.PASTEBIN);

    if (DOM.advancedModeButton) {
        DOM.advancedModeButton.addEventListener('click', openAdvancedDashboard);
    }

    removeOverlay();

    const observer = new MutationObserver(() => {
        removeOverlay();
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    console.info('Application initialized successfully');
};

document.addEventListener('DOMContentLoaded', init);

window.openTab = openTab;
window.closeVideoWindow = closeVideoWindow;

function openTab(evt, tabName) {
    const tabcontent = document.getElementsByClassName('tabcontent');
    for (let i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = 'none';
    }

    const tablinks = document.getElementsByClassName('tablinks');
    for (let i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(' active', '');
    }

    document.getElementById(tabName).style.display = 'block';
    evt.currentTarget.className += ' active';
}
