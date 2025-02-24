// Constants
const API_ENDPOINTS = {
    IP_INFO: 'http://ip-api.com/json/',
    IP_INFO_FIELDS: 'status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query',
    PASTEBIN: 'https://pastebin.com/raw/UuJZFNxF',
    CORS_PROXY: 'https://serverless-api-jnzf.vercel.app/api/proxy',
    ASN_INFO: 'https://ipinfo.io/'
};

// State
let globalState = {
    latitude: null,
    longitude: null,
    asn: null,
};

// DOM Elements
const DOM = {
    cameraList: document.getElementById('cameraList'),
    addIpForm: document.getElementById('addIpForm'),
    addIpInput: document.getElementById('addIpInput'),
    addIpButton: document.getElementById('addIpButton'),
    sidebar: document.getElementById('sidebar'),
    windowTitlebar: document.getElementById('windowTitlebar')
};

// Helper Functions
const extractIpFromRtsp = (rtspUrl) => rtspUrl.match(/(\d+\.\d+\.\d+\.\d+)/)[0];

const createElementWithClass = (tag, className) => {
    const element = document.createElement(tag);
    element.className = className;
    return element;
};

async function fetchJson(url) {
    const response = await fetch(url);
    if (!response.ok) {
        const errorMessage = await response.text(); // Capture error message from response
        throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorMessage}`);
    }
    return response.json();
}

document.getElementById('addIpForm').addEventListener('submit', (event) => {
    event.preventDefault(); // Prevent the form from submitting normally
    const ipInput = document.getElementById('addIpInput').value.trim();

    // Validate the RTSP or MJPG URL format (basic validation example)
    const rtspRegex = /^rtsp:\/\/(:\S*)?@?(\d{1,3}\.){3}\d{1,3}:\d{1,5}(\/.*)?$/;
    const mjpgRegex = /^http:\/\/(:\S*)?@?(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?(\/.*)?$/;

    if (!rtspRegex.test(ipInput) && !mjpgRegex.test(ipInput)) {
        alert('Invalid URL format. Please use the format: rtsp://:@<IP_ADDRESS>:<PORT>/ or http://:@<IP_ADDRESS>:<PORT>/');
        return;
    }

    // Create a new list item
    const cameraList = document.getElementById('cameraList');
    const newItem = document.createElement('li');
    newItem.classList.add('camera-list-item');
    newItem.textContent = ipInput;

    // Add click event listener to the new item
    newItem.addEventListener('click', () => openVideoWindow(ipInput));

    // Insert at the beginning of the list
    cameraList.insertBefore(newItem, cameraList.firstChild);

    // Clear the input field
    document.getElementById('addIpInput').value = '';
});


// Function to remove the overlay link
function removeOverlay() {
    const overlay = document.getElementById('overlay');
    if (overlay) {
        overlay.remove();
        console.log('Overlay removed.');
    }
}

// Initial call to remove the overlay if it already exists
removeOverlay();

// Use a MutationObserver to detect when new nodes are added to the DOM
const observer = new MutationObserver(() => {
    removeOverlay();
});

// Start observing the document body for added nodes
observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Draggable Functionality
const makeDraggable = (windowElement, titlebarElement) => {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
    titlebarElement.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
        e = e || window.event;
        e.preventDefault();
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        document.onmousemove = elementDrag;
    }

    function elementDrag(e) {
        e = e || window.event;
        e.preventDefault();
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        windowElement.style.top = (windowElement.offsetTop - pos2) + "px";
        windowElement.style.left = (windowElement.offsetLeft - pos1) + "px";
    }

    function closeDragElement() {
        document.onmouseup = null;
        document.onmousemove = null;
    }
};

// Main Functions
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

const updateCameraListFromPastebin = async (pastebinUrl) => {
    const plainTextContent = await fetchPastebinContent(pastebinUrl);
    const rtspUrls = plainTextContent.split('\n').filter(url => url.trim() !== '');
    updateCameraList(rtspUrls);
};

const updateCameraList = (ipList) => {
    DOM.cameraList.innerHTML = '';
    ipList.forEach(ip => {
        const listItem = createElementWithClass('li', 'camera-list-item');
        listItem.textContent = ip;
        listItem.addEventListener('click', () => openVideoWindow(ip));
        DOM.cameraList.appendChild(listItem);
    });
};

const openVideoWindow = (url) => {
    const newWindow = createVideoWindow(url);
    document.body.appendChild(newWindow);
    makeDraggable(newWindow, newWindow.querySelector('.window-titlebar'));
    fetchIPInfo(url);
};

const createVideoWindow = (url) => {
    const newWindow = createElementWithClass('div', 'window video-container');
    let iframeSrc;

    if (url.startsWith('rtsp://')) {
        iframeSrc = `https://streamedian.com/embed?w=ZXVwLnN0cmVhbWVkaWFuLmNvbQ==&s=${btoa(url)}&r=MTI4MHg3MjA=`;
    } else if (url.startsWith('http://')) {
        iframeSrc = url; // Directly use MJPG URL
    }

    newWindow.innerHTML = `
        <div class="window-titlebar">
            <span id="videoTitle">${url}</span>
            <button class="close-button" onclick="closeVideoWindow()">Close</button>
        </div>
        <div class="window-content" style="height: 950px; width: 1300px; display: flex;">
            <div class="video-section" style="flex: 1;">
                <iframe id="videoFrame" class="video-player" frameborder="0" allowfullscreen="1"
                    src="${iframeSrc}" width="800" height="450"></iframe>
                <div class="google-maps" id="googleMaps"></div>
            </div>
            <div class="window-content" style="height: 750px; width: 800px;">
                <!-- Tab navigation -->
                <div class="tab">
                    <button class="tablinks button-89" onclick="openTab(event, 'ip-info')">IP Info</button>
                    <button class="tablinks button-89" onclick="openTab(event, 'asn-site')">ASN</button>
                    <button class="tablinks button-89" onclick="openTab(event, 'ip-reputation')">IP reputation</button>
                    <button class="tablinks button-89" onclick="openTab(event, 'osint')">OSINT</button>
                    <button class="tablinks button-89" onclick="openTab(event, 'useful-website')">Useful Links</button>
                </div>
                <hr>
                <!-- Tab content -->
                <div id="ip-info" class="tabcontent" style="display: none;">
                    <div id="loadingMessage">Fetching IP information...</div>
                    <div id="ipInfo" style="display: none;"></div>
                </div>
                <div id="ip-reputation" class="tabcontent" style="display: none;">
                    <button class="button-29" onclick="window.open('https://talosintelligence.com/reputation_center/lookup?search=${extractIpFromRtsp(url)}')">Check IP Reputation</button>
                </div>
                <div id="asn-site" class="tabcontent" style="display: none;"></div>
                <div id="osint" class="tabcontent" style="display: none;">
                    <p>OSINT: <button class="button-29" onclick="window.open('https://osintframework.com')">[osintframework]</button></p>
                    <p>OSINT tool for email&phone number: <button class="button-29" onclick="window.open('https://epieos.com')">[epieos]</button></p>
                    <p>OSINT tool: <button class="button-29" onclick="window.open('https://thatsthem.com')">[thatsthem]</button></p>
                    <p>OSINT tool: <button class="button-29" onclick="window.open('https://dehashed.com')">[dehashed]</button></p>
                    <p>Email reputation: <button class="button-29" onclick="window.open('https://emailrep.io')">[emailrep]</button></p>
                    <p>Search Username (actually scary): <button class="button-29" onclick="window.open('https://www.peekyou.com/username')">[peekyou]</button></p>
                    <button class="button-29" onclick="window.open('https://instantusername.com')">[instantusername]</button>
                    <button class="button-29" onclick="window.open('https://searchpof.com')">[searchpof]</button>
                    <button class="button-29" onclick="window.open('https://www.namecheckr.com')">[namecheckr]</button>
                    <button class="button-29" onclick="window.open('https://checkusernames.com')">[checkusernames]</button>
                    <p>Was email leaked?: <button class="button-29" onclick="window.open('https://haveibeenpwned.com')">[haveibeenpwned]</button></p>
                    <p>Use email in linkedin: https://www.linkedin.com/sales/gmail/profile/viewByEmail/(email)</p>
                </div>
                <div id="useful-website" class="tabcontent" style="display: none;">
                    <p>Good Web RTSP Player: <button class="button-29" onclick="window.open('https://www.ipcamlive.com/streamtest')">[ipcamlive]</button></p>
                    <p>${url}</p>
                    <p>Another WHOIS:</p>
                    <button class="button-29" onclick="window.open('https://1d4.us/search?q=${url.match(/(\d+\.\d+\.\d+\.\d+)/)[0]}')">[1d4.us]</button>
                    <button class="button-29" onclick="window.open('https://wq.apnic.net/static/search.html')">[wq.apnic.net]</button>
                    <p>Use google earth for 3D feature: <button class="button-29" onclick="window.open('https://earth.google.com')">[Google Earth]</button></p>
                    <p>https://earth.google.com/web/@<latitude>,<longitude>,<altitude>,<heading>,<tilt>,<roll>/data=<parameters></p>
                    <p>Use ASN, I'm lazy to do it: <button class="button-29" onclick="window.open('https://bgp.he.net/')">[bgp.he.net]</button></p>
                </div>
            </div>
        </div>
    `;

    return newWindow;
};

function showLoadingMessage(isLoading) {
    const loadingElement = document.getElementById('loadingMessage'); // Ensure you have an element for this
    if (isLoading) {
        loadingElement.style.display = 'block'; // Show the loading message
    } else {
        loadingElement.style.display = 'none'; // Hide the loading message
    }
}

async function fetchIPInfo(rtspUrl) {
    const ip = extractIpFromRtsp(rtspUrl);
    if (!ip) {
        console.error('Invalid IP address extracted from RTSP URL.');
        return;
    }
    console.log(`Extracted IP: ${ip}`);

    // Show loading message
    showLoadingMessage(true);
    
    // Start a timer to update the UI every second
    const intervalId = setInterval(() => {
        updateLoadingUI();
    }, 1000);

    try {
        const url = `${API_ENDPOINTS.IP_INFO}${ip}?fields=${API_ENDPOINTS.IP_INFO_FIELDS}`;
        console.log(`Constructed URL: ${url}`);

        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorMessage}`);
        }

        const ipInfo = await response.json();
        console.log('IP Info Response:', ipInfo); // Log the response

        if (!ipInfo || !ipInfo.contents) {
            console.error('IP information not found or invalid structure:', ipInfo);
            return;
        }

        // Parse the contents of the response
        const parsedData = JSON.parse(ipInfo.contents);
        if (!parsedData || !parsedData.query) {
            console.error('Parsed IP information not found or invalid structure:', parsedData);
            return;
        }

        // Update the UI with the fetched information
        updateIPInfoUI(parsedData);
        globalState.latitude = parsedData.lat;
        globalState.longitude = parsedData.lon;

        fetchAndUpdateASN(ip, parsedData.asname);

    } catch (error) {
        console.error('Failed to fetch IP information:', error.message);
    } finally {
        // Stop the loading UI update and hide the loading message
        clearInterval(intervalId);
        showLoadingMessage(false);
    }
}

// Function to update the loading UI every second
const updateLoadingUI = () => {
    const loadingMessage = document.getElementById('loadingMessage');
    if (loadingMessage) {
        loadingMessage.innerText = 'Fetching IP information...';
    }
};

// Function to update the UI with fetched IP information
const updateIPInfoUI = (data) => {
    const ipInfo = document.getElementById('ipInfo');
    ipInfo.innerHTML = `
        <p><strong>Status:</strong> ${data.status}</p>
        <p><strong>Message:</strong> ${data.message}</p>
        <p><strong>Continent:</strong> ${data.continent} (${data.continentCode})</p>
        <p><strong>Country:</strong> ${data.country} (${data.countryCode})</p>
        <p><strong>Region:</strong> ${data.regionName} (${data.region})</p>
        <p><strong>City:</strong> ${data.city}</p>
        <p><strong>District:</strong> ${data.district}</p>
        <p><strong>ZIP Code:</strong> ${data.zip}</p>
        <p><strong>Latitude:</strong> ${data.lat}</p>
        <p><strong>Longitude:</strong> ${data.lon}</p>
        <p><strong>Timezone:</strong> ${data.timezone}</p>
        <p><strong>Offset:</strong> ${data.offset}</p>
        <p><strong>Currency:</strong> ${data.currency}</p>
        <p><strong>ISP:</strong> ${data.isp}</p>
        <p><strong>Organization:</strong> ${data.org}</p>
        <p><strong>ASN:</strong> ${data.as}</p>
        <p><strong>ASN Name:</strong> ${data.asname}</p>
        <p><strong>Reverse DNS:</strong> ${data.reverse}</p>
        <p><strong>Mobile:</strong> ${data.mobile}</p>
        <p><strong>Proxy:</strong> ${data.proxy}</p>
        <p><strong>Hosting:</strong> ${data.hosting}</p>
        <p><strong>Query:</strong> ${data.query}</p>
    `;

    // Show the IP info and hide the loading message
    ipInfo.style.display = 'block';  // Set to 'block' to make it visible
    const loadingMessage = document.getElementById('loadingMessage');
    loadingMessage.style.display = 'none'; // Hide loading message

    updateGoogleMaps(data.lat, data.lon, data.district, data.city, data.region);
};

const updateGoogleMaps = (lat, lon, district, city, regionName) => {
    const googleMaps = document.getElementById('googleMaps');
    googleMaps.innerHTML = `
        <iframe width="90%" height="487px" frameborder="0" style="border:0" 
        src="https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;coord=${lat},${lon}&amp;q=1%20${district}%20Street%2C%20${city}%2C%20${regionName}&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed" 
        allowfullscreen></iframe>
    `;
};

async function fetchAndUpdateASN(ip, asn) {
    if (!ip) {
        console.error('No IP address available for ASN lookup.');
        return;
    }
    console.log(`Fetching ASN for IP: ${ip}`); // Debugging log

    try {
        // Construct the URL for ASN info API
        const url = `${API_ENDPOINTS.ASN_INFO}${ip}/json`;
        console.log(`Constructed ASN URL: ${url}`);

        // Make the fetch request using the CORS proxy
        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }) // Send the constructed URL in the body
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const asnInfo = await response.json();

        console.log('ASN Info Response:', asnInfo);

        const data = JSON.parse(asnInfo.contents); 

        updateASNInfoUI(data);

        globalState.asn = data.org || 'Unknown ASN';

    } catch (error) {
        console.error('Failed to fetch ASN information:', error.message);
    }
}

const updateASNInfoUI = (asnData) => {
    const asnSiteTab = document.getElementById('asn-site');
    asnSiteTab.innerHTML = `
        <h2>ASN Information</h2>
        <p><strong>IP:</strong> ${asnData.ip}</p>
        <p><strong>Hostname:</strong> ${asnData.hostname}</p>
        <p><strong>City:</strong> ${asnData.city}</p>
        <p><strong>Region:</strong> ${asnData.region}</p>
        <p><strong>Country:</strong> ${asnData.country}</p>
        <p><strong>Organization:</strong> ${asnData.org}</p>
        <p><strong>Postal Code:</strong> ${asnData.postal}</p>
        <p><strong>Timezone:</strong> ${asnData.timezone}</p>
        <p><strong>Location:</strong> ${asnData.loc}</p>
    `;

    // Display the ASN information section
    asnSiteTab.style.display = 'block';
    removeOverlay();
};

// Tab functionality
const openTab = (evt, tabName) => {
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
};

// Close video window
const closeVideoWindow = () => {
    const videoContainer = document.querySelector('.video-container');
    videoContainer.remove();
};

// Event Listeners
DOM.addIpForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const newIp = DOM.addIpInput.value.trim();
    if (newIp) {
        try {
            await fetch('/add-ip', {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                body: newIp
            });
            const currentIps = [...document.querySelectorAll('.camera-list-item')].map(item => item.textContent);
            updateCameraList([...currentIps, newIp]);
            DOM.addIpInput.value = '';
        } catch (error) {
            console.error('Error adding IP address:', error);
        }
    }
});

// Initialization
const init = () => {
    updateCameraListFromPastebin(API_ENDPOINTS.PASTEBIN);
    makeDraggable(DOM.sidebar, DOM.windowTitlebar);
};

// Run initialization
init();
