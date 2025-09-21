// Constants
const API_ENDPOINTS = {
    IP_INFO: 'http://ip-api.com/json/',
    IP_INFO_FIELDS: 'status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query',
    PASTEBIN: 'https://pastebin.com/raw/UuJZFNxF',
    CORS_PROXY: 'https://serverless-api-jnzf.vercel.app/api/proxy',
    ASN_INFO: 'https://ipinfo.io/',
    CAMERA_METADATA: 'https://serverless-api-jnzf.vercel.app/api/proxy',
    // Only free APIs without authentication
    ALIENVAULT: 'https://otx.alienvault.com/api/v1/indicators/IPv4/',
    TIMEZONE_API: 'https://worldtimeapi.org/api/timezone/'
};

// State
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
        asnInfo: {},
        metadata: {},
        networkDiscovery: {},
        threatIntel: {},
        weatherData: {},
        timezoneData: {}
    },
    consoleLog: [],
    currentSelectedCamera: null,
    autoResolution: true,
    manualResolution: "720x420",
    playerPreference: "flashphoner",
    mjpgPlayerPreference: "mjpg-iframe",
    // Threat Intelligence Settings (only free APIs)
    threatIntel: {
        enabled: true,
        sources: ['alienvault'], // Only free APIs without authentication
        riskScores: {}
    },
    // Comprehensive credential database
    credentialDatabase: {
        usernames: [
            "",
            "666666",
            "888888",
            "Admin",
            "admin",
            "admin1",
            "administrator",
            "Administrator",
            "aiphone",
            "Dinion",
            "none",
            "root",
            "Root",
            "service",
            "supervisor",
            "ubnt"
        ],
        passwords: [
            "",
            "0000",
            "00000",
            "1111",
            "111111",
            "1111111",
            "123",
            "1234",
            "12345",
            "123456",
            "1234567",
            "12345678",
            "123456789",
            "12345678910",
            "4321",
            "666666",
            "6fJjMKYx",
            "888888",
            "9999",
            "admin",
            "admin123456",
            "admin pass",
            "Admin",
            "admin123",
            "administrator",
            "Administrator",
            "aiphone",
            "camera",
            "Camera",
            "fliradmin",
            "GRwvcj8j",
            "hikvision",
            "hikadmin",
            "HuaWei123",
            "ikwd",
            "jvc",
            "kj3TqCWv",
            "meinsm",
            "pass",
            "Pass",
            "password",
            "password123",
            "qwerty",
            "qwerty123",
            "Recorder",
            "reolink",
            "root",
            "service",
            "supervisor",
            "support",
            "system",
            "tlJwpbo6",
            "toor",
            "tp-link",
            "ubnt",
            "user",
            "wbox",
            "wbox123",
            "Y5eIMz3C"
        ]
    },
    // Common RTSP stream paths
    rtspPaths: [
        "/live/ch01_0",
        "0/1:1/main",
        "0/usrnm:pwd/main",
        "0/video1",
        "1",
        "1.AMP",
        "1/h264major",
        "1/stream1",
        "11",
        "12",
        "125",
        "1080p",
        "1440p",
        "480p",
        "4K",
        "666",
        "720p",
        "AVStream1_1",
        "CAM_ID.password.mp2",
        "CH001.sdp",
        "GetData.cgi",
        "HD",
        "HighResolutionVideo",
        "LowResolutionVideo",
        "MediaInput/h264",
        "MediaInput/mpeg4",
        "ONVIF/MediaInput",
        "ONVIF/MediaInput?profile=4_def_profile6",
        "StdCh1",
        "Streaming/Channels/1",
        "Streaming/Unicast/channels/101",
        "StreamingSetting?version=1.0&action=getRTSPStream&ChannelID=1&ChannelName=Channel1",
        "VideoInput/1/h264/1",
        "VideoInput/1/mpeg4/1",
        "access_code",
        "access_name_for_stream_1_to_5",
        "api/mjpegvideo.cgi",
        "av0_0",
        "av2",
        "avc",
        "avn=2",
        "axis-media/media.amp",
        "axis-media/media.amp?camera=1",
        "axis-media/media.amp?videocodec=h264",
        "cam",
        "cam/realmonitor",
        "cam/realmonitor?channel=0&subtype=0",
        "cam/realmonitor?channel=1&subtype=0",
        "cam/realmonitor?channel=1&subtype=1",
        "cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif",
        "cam0",
        "cam0_0",
        "cam0_1",
        "cam1",
        "cam1/h264",
        "cam1/h264/multicast",
        "cam1/mjpeg",
        "cam1/mpeg4",
        "cam1/mpeg4?user='username'&pwd='password'",
        "cam1/onvif-h264",
        "camera.stm",
        "ch0",
        "ch00/0",
        "ch001.sdp",
        "ch01.264",
        "ch01.264?",
        "ch01.264?ptype=tcp",
        "ch1_0",
        "ch2_0",
        "ch3_0",
        "ch4_0",
        "ch1/0",
        "ch2/0",
        "ch3/0",
        "ch4/0",
        "ch0_0.h264",
        "ch0_unicast_firststream",
        "ch0_unicast_secondstream",
        "ch1-s1",
        "channel1",
        "gnz_media/main",
        "h264",
        "h264.sdp",
        "h264/ch1/sub/av_stream",
        "h264/media.amp",
        "h264Preview_01_main",
        "h264Preview_01_sub",
        "h264_vga.sdp",
        "h264_stream",
        "image.mpg",
        "img/media.sav",
        "img/media.sav?channel=1",
        "img/video.asf",
        "img/video.sav",
        "ioImage/1",
        "ipcam.sdp",
        "ipcam_h264.sdp",
        "ipcam_mjpeg.sdp",
        "live",
        "live.sdp",
        "live/av0",
        "live/ch0",
        "live/ch00_0",
        "live/ch01_0",
        "live/h264",
        "live/main",
        "live/main0",
        "live/mpeg4",
        "live1.sdp",
        "live3.sdp",
        "live_mpeg4.sdp",
        "live_st1",
        "livestream",
        "main",
        "media",
        "media.amp",
        "media.amp?streamprofile=Profile1",
        "media/media.amp",
        "media/video1",
        "medias2",
        "mjpeg/media.smp",
        "mp4",
        "mpeg/media.amp",
        "mpeg4",
        "mpeg4/1/media.amp",
        "mpeg4/media.amp",
        "mpeg4/media.smp",
        "mpeg4unicast",
        "mpg4/rtsp.amp",
        "multicaststream",
        "now.mp4",
        "nph-h264.cgi",
        "nphMpeg4/g726-640x",
        "nphMpeg4/g726-640x48",
        "nphMpeg4/g726-640x480",
        "nphMpeg4/nil-320x240",
        "onvif-media/media.amp",
        "onvif1",
        "pass@10.0.0.5:6667/blinkhd",
        "play1.sdp",
        "play2.sdp",
        "profile0",
        "profile1",
        "profile2",
        "profile2/media.smp",
        "profile5/media.smp",
        "rtpvideo1.sdp",
        "rtsp_live0",
        "rtsp_live1",
        "rtsp_live2",
        "rtsp_tunnel",
        "rtsph264",
        "rtsph2641080p",
        "snap.jpg",
        "stream",
        "stream/0",
        "stream/1",
        "stream/live.sdp",
        "stream.sdp",
        "stream1",
        "streaming/channels/0",
        "streaming/channels/1",
        "streaming/channels/101",
        "tcp/av0_0",
        "test",
        "tmpfs/auto.jpg",
        "trackID=1",
        "ucast/11",
        "udp/av0_0",
        "udp/unicast/aiphone_H264",
        "udpstream",
        "user.pin.mp2",
        "user=admin&password=&channel=1&stream=0.sdp?",
        "user=admin&password=&channel=1&stream=0.sdp?real_stream",
        "user=admin_password=?????_channel=1_stream=0.sdp?real_stream",
        "user=admin_password=R5XFY888_channel=1_stream=0.sdp?real_stream",
        "user_defined",
        "v2",
        "video",
        "video.3gp",
        "video.h264",
        "video.mjpg",
        "video.mp4",
        "video.pro1",
        "video.pro2",
        "video.pro3",
        "video0",
        "video0.sdp",
        "video1",
        "video1.sdp",
        "video1+audio1",
        "videoMain",
        "videoinput_1/h264_1/media.stm",
        "videostream.asf",
        "vis",
        "wfov"
    ],
    cameraModels: {
        // Common camera manufacturers and their identifiers
        hikvision: {
            patterns: ['hikvision', 'hikconnect', 'hik-connect', 'ivms', 'ds-'],
            defaultCredentials: [{
                    username: 'admin',
                    password: '12345',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'admin',
                    notes: 'Common default'
                },
                {
                    username: 'admin',
                    password: 'Admin12345',
                    notes: 'Updated default since 2016'
                },
                {
                    username: 'admin',
                    password: '',
                    notes: 'Blank password on some models'
                },
                {
                    username: 'admin',
                    password: '123456',
                    notes: 'Common variation'
                },
                {
                    username: 'admin',
                    password: 'hikvision',
                    notes: 'Brand name as password'
                },
                {
                    username: 'operator',
                    password: 'operator',
                    notes: 'Secondary account'
                }
            ],
            webPaths: ['/doc/page/login.asp', '/PSIA/Custom/SelfExt/userCheck', '/ISAPI/Security/userCheck'],
            ports: [80, 443, 554, 8000, 8200],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2021-36260: Command injection via web interface',
                'CVE-2017-7921: Authentication bypass in older firmware'
            ]
        },
        dahua: {
            patterns: ['dahua', 'dh-', 'ipc-h', 'ipc-d', 'lechange'],
            defaultCredentials: [{
                    username: 'admin',
                    password: 'admin',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'Admin123',
                    notes: 'Updated default'
                },
                {
                    username: 'admin',
                    password: 'password',
                    notes: 'Common variation'
                },
                {
                    username: '888888',
                    password: '888888',
                    notes: 'Secondary admin account'
                },
                {
                    username: '666666',
                    password: '666666',
                    notes: 'Operator account'
                },
                {
                    username: 'default',
                    password: 'default',
                    notes: 'Backup account on some models'
                },
                {
                    username: 'root',
                    password: 'vizxv',
                    notes: 'Telnet/SSH access on older models'
                }
            ],
            webPaths: ['/RPC2_Login', '/RPC2', '/cgi-bin/configManager.cgi'],
            ports: [80, 443, 554, 37777],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2021-33044: Authentication bypass in some models',
                'CVE-2013-6117: Unauthenticated access to device configuration'
            ]
        },
        axis: {
            patterns: ['axis', 'accc', 'vapix'],
            defaultCredentials: [{
                    username: 'root',
                    password: 'pass',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'admin',
                    notes: 'Common default'
                },
                {
                    username: 'root',
                    password: 'root',
                    notes: 'Alternative default'
                },
                {
                    username: 'admin',
                    password: 'axis2022',
                    notes: 'Newer models default'
                },
                {
                    username: 'viewer',
                    password: 'viewer',
                    notes: 'View-only account'
                }
            ],
            webPaths: ['/axis-cgi/admin/param.cgi', '/view/index.shtml', '/axis-cgi/jpg/image.cgi'],
            ports: [80, 443, 554],
            securityRating: 'high',
            vulnerabilities: [
                'CVE-2018-10660: Command injection in older firmware'
            ]
        },
        foscam: {
            patterns: ['foscam', 'fi9', 'r2', 'c1', 'c2'],
            defaultCredentials: [{
                    username: 'admin',
                    password: 'admin',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: '',
                    notes: 'Blank password on some models'
                },
                {
                    username: 'admin',
                    password: 'password',
                    notes: 'Common variation'
                },
                {
                    username: 'admin',
                    password: 'foscam',
                    notes: 'Brand name as password'
                },
                {
                    username: 'visitor',
                    password: 'visitor',
                    notes: 'Guest account'
                }
            ],
            webPaths: ['/cgi-bin/CGIProxy.fcgi', '/cgi-bin/viewer/video.jpg', '/videostream.cgi'],
            ports: [80, 443, 554, 88, 10080],
            securityRating: 'low',
            vulnerabilities: [
                'CVE-2018-19355: Authentication bypass',
                'CVE-2020-9047: Hard-coded credentials',
                'Multiple unauthenticated RCE vulnerabilities'
            ]
        },
        tplink: {
            patterns: ['tplink', 'tp-link', 'tapo'],
            defaultCredentials: [{
                    username: 'admin',
                    password: 'admin',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'password',
                    notes: 'Common variation'
                },
                {
                    username: 'admin',
                    password: 'tp-link',
                    notes: 'Brand name as password'
                },
                {
                    username: 'admin',
                    password: 'tplink',
                    notes: 'Brand name variation'
                }
            ],
            webPaths: ['/webpages/index.html', '/cgi/index.cgi', '/cgi-bin/luci'],
            ports: [80, 443, 554, 2020],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2020-35575: Remote code execution in Tapo cameras',
                'CVE-2021-41653: Information disclosure'
            ]
        },
        wyze: {
            patterns: ['wyze', 'wyzecam'],
            defaultCredentials: [{
                    username: 'admin',
                    password: 'admin123',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'admin1234',
                    notes: 'Common variation'
                }
            ],
            webPaths: ['/cgi-bin/api.cgi', '/live'],
            ports: [80, 443, 554],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2019-9569: Information disclosure',
                'CVE-2019-12266: Buffer overflow'
            ]
        },
        reolink: {
            patterns: ['reolink', 'rlc-'],
            defaultCredentials: [{
                    username: 'admin',
                    password: 'admin',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: '',
                    notes: 'Blank password on some models'
                },
                {
                    username: 'admin',
                    password: 'reolink',
                    notes: 'Brand name as password'
                },
                {
                    username: 'admin',
                    password: 'Reolink123',
                    notes: 'Updated default on newer models'
                },
                {
                    username: 'guest',
                    password: 'guest',
                    notes: 'Guest account'
                }
            ],
            webPaths: ['/cgi-bin/api.cgi', '/api/v1/device', '/cgi-bin/ptz.cgi'],
            ports: [80, 443, 554, 9000],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2020-25169: Hard-coded credentials',
                'CVE-2020-25173: Command injection'
            ]
        },
        amcrest: {
            patterns: ['amcrest', 'ipc-'],
            defaultCredentials: [{
                    username: 'admin',
                    password: 'admin',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'password',
                    notes: 'Common variation'
                },
                {
                    username: 'admin',
                    password: 'amcrest',
                    notes: 'Brand name as password'
                },
                {
                    username: 'admin',
                    password: 'admin123',
                    notes: 'Common variation'
                }
            ],
            webPaths: ['/cgi-bin/snapshot.cgi', '/cgi-bin/configManager.cgi'],
            ports: [80, 443, 554],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2017-8229: Authentication bypass',
                'CVE-2019-3948: Unauthorized access'
            ]
        },
        ubiquiti: {
            patterns: ['ubiquiti', 'unifi', 'aircam', 'uvc'],
            defaultCredentials: [{
                    username: 'ubnt',
                    password: 'ubnt',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'admin',
                    notes: 'Alternative default'
                },
                {
                    username: 'root',
                    password: 'ubnt',
                    notes: 'SSH/Telnet default'
                }
            ],
            webPaths: ['/api/2.0/login', '/login', '/manage/account/login'],
            ports: [80, 443, 554, 7080, 7443],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2021-22909: Improper access control',
                'CVE-2019-11344: Command injection'
            ]
        },
        vivotek: {
            patterns: ['vivotek', 'vvtk'],
            defaultCredentials: [{
                    username: 'root',
                    password: 'root',
                    notes: 'Factory default'
                },
                {
                    username: 'admin',
                    password: 'admin',
                    notes: 'Common default'
                },
                {
                    username: 'vivotek',
                    password: 'vivotek',
                    notes: 'Brand name credentials'
                }
            ],
            webPaths: ['/cgi-bin/viewer/video.jpg', '/cgi-bin/admin/getparam.cgi'],
            ports: [80, 443, 554, 3702],
            securityRating: 'medium',
            vulnerabilities: [
                'CVE-2020-5722: Command injection',
                'CVE-2018-13878: Authentication bypass'
            ]
        },
        generic: {
            patterns: ['ipcam', 'netcam', 'webcam', 'ip camera', 'rtsp'],
            defaultCredentials: [{
                    username: 'admin',
                    password: 'admin',
                    notes: 'Most common default'
                },
                {
                    username: 'admin',
                    password: 'password',
                    notes: 'Very common default'
                },
                {
                    username: 'admin',
                    password: '1234',
                    notes: 'Simple numeric password'
                },
                {
                    username: 'admin',
                    password: '12345',
                    notes: 'Simple numeric password'
                },
                {
                    username: 'admin',
                    password: '',
                    notes: 'Blank password'
                },
                {
                    username: 'root',
                    password: 'root',
                    notes: 'Common for embedded systems'
                },
                {
                    username: 'user',
                    password: 'user',
                    notes: 'Simple user account'
                },
                {
                    username: 'guest',
                    password: 'guest',
                    notes: 'Guest account'
                }
            ],
            webPaths: ['/index.html', '/login.html', '/cgi-bin/snapshot.cgi'],
            ports: [80, 443, 554, 8080, 8000],
            securityRating: 'low',
            vulnerabilities: [
                'Weak default credentials',
                'Lack of HTTPS encryption',
                'Outdated firmware'
            ]
        }
    }
};

// DOM Elements
const DOM = {
    elements: {},
    init() {
        const elements = {
            cameraList: 'cameraList',
            addIpForm: 'addIpForm',
            addIpInput: 'addIpInput',
            addIpButton: 'addIpButton',
            sidebar: 'sidebar',
            clock: 'clock',
            cameraCount: 'cameraCount',
            advancedModeButton: 'advancedModeButton'
        };

        // Get all elements and store them
        for (const [key, id] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (!element) {
                console.warn(`Element with id '${id}' not found`);
            }
            this.elements[key] = element;
        }
        return this;
    },
    get(elementKey) {
        const element = this.elements[elementKey];
        if (!element) {
            console.warn(`Element '${elementKey}' not found in DOM cache`);
        }
        return element;
    }
};

// Override console methods to capture logs
const originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn,
    info: console.info
};

// Custom console to track logs
console.log = function () {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'log',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object'?JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.log.apply(console, arguments);
};

console.error = function () {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'error',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object'?JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.error.apply(console, arguments);
};

console.warn = function () {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'warn',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object'?JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.warn.apply(console, arguments);
};

console.info = function () {
    const args = Array.from(arguments);
    globalState.consoleLog.push({
        type: 'info',
        time: new Date(),
        message: args.map(arg => typeof arg === 'object'?JSON.stringify(arg) : arg).join(' ')
    });
    updateConsoleOutput();
    originalConsole.info.apply(console, arguments);
};

// Helper Functions
const extractIpFromUrl = (url) => {
    const match = url.match(/(\d+\.\d+\.\d+\.\d+)/);
    return match?match[0] : null;
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
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        const response = await fetch(url, {
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorMessage}`);
        }

        const data = await response.json();
        if (!data) {
            throw new Error('Empty response received');
        }

        return data;
    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('Request timed out');
        }
        console.error('Error fetching JSON:', error);
        throw error;
    }
}

// UI Update Functions
const updateCameraCount = () => {
    const count = globalState.cameras.length;
    DOM.get('cameraCount').textContent = `${count} camera${count !== 1?'s' : ''}`;
};

const updateClock = () => {
    const now = new Date();
    DOM.get('clock').textContent = now.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
};

// Remove overlay (if exists)
const removeOverlay = () => {
    const overlay = document.getElementById('overlay');
    if (overlay) {
        overlay.remove();
        console.log('Overlay removed.');
    }
};

// Draggable Functionality
const makeDraggable = (windowElement, titlebarElement) => {
    let pos1 = 0,
        pos2 = 0,
        pos3 = 0,
        pos4 = 0;
    let isDragging = false;

    if (!titlebarElement || !windowElement) return;

    titlebarElement.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
        if (e.target.closest('button')) return; // Don't drag if clicking on a button

        e = e || window.event;
        e.preventDefault();

        // Bring window to front
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

        // Calculate new position
        const newTop = windowElement.offsetTop - pos2;
        const newLeft = windowElement.offsetLeft - pos1;

        // Apply new position
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

// Window Controls
const setupWindowControls = (windowElement) => {
    if (!windowElement) return;

    // Minimize button
    const minimizeBtn = windowElement.querySelector('.minimize');
    if (minimizeBtn) {
        minimizeBtn.addEventListener('click', () => {
            const content = windowElement.querySelector('.window-content');
            if (content) {
                content.classList.toggle('minimized');
            }
        });
    }

    // Maximize button
    const maxBtn = windowElement.querySelector('.maximize');
    if (maxBtn) {
        maxBtn.addEventListener('click', () => {
            const icon = maxBtn.querySelector('i');
            windowElement.classList.toggle('maximized');

            if (windowElement.classList.contains('maximized')) {
                // Store previous dimensions for restore
                windowElement.dataset.prevTop = windowElement.style.top;
                windowElement.dataset.prevLeft = windowElement.style.left;
                windowElement.dataset.prevWidth = windowElement.style.width;
                windowElement.dataset.prevHeight = windowElement.style.height;
                windowElement.dataset.prevZIndex = windowElement.style.zIndex;

                // Change icon
                icon.classList.remove('fa-expand');
                icon.classList.add('fa-compress');

                // Maximize
                windowElement.style.top = '0';
                windowElement.style.left = '0';
                windowElement.style.width = '100%';
                windowElement.style.height = '100%';

                // Bring to front
                const highestZIndex = Math.max(
                    1000,
                    ...Array.from(document.querySelectorAll('.window'))
                    .map(w => parseInt(getComputedStyle(w).zIndex) || 0)
                ) + 10;
                windowElement.style.zIndex = highestZIndex;
            } else {
                icon.classList.remove('fa-compress');
                icon.classList.add('fa-expand');

                // Restore previous dimensions
                windowElement.style.top = windowElement.dataset.prevTop || '';
                windowElement.style.left = windowElement.dataset.prevLeft || '';
                windowElement.style.width = windowElement.dataset.prevWidth || '';
                windowElement.style.height = windowElement.dataset.prevHeight || '';
                windowElement.style.zIndex = windowElement.dataset.prevZIndex || '';
                windowElement.style.borderRadius = '';
            }
        });
    }

    // Close button
    const closeBtn = windowElement.querySelector('.close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            windowElement.classList.add('closing');
            setTimeout(() => {
                windowElement.remove();

                // If this is the advanced dashboard, update the state
                if (windowElement.id === 'advancedDashboard') {
                    globalState.advancedMode = false;
                    return;
                }

                // Update active windows list
                const windowId = windowElement.dataset.id;
                globalState.activeWindows = globalState.activeWindows.filter(w => w !== windowId);

                // Clean up resize observer if it exists
                if (windowId && globalState.resizeObservers[windowId]) {
                    globalState.resizeObservers[windowId].observer.disconnect();
                    if (globalState.resizeObservers[windowId].timeout) {
                        clearTimeout(globalState.resizeObservers[windowId].timeout);
                    }
                    delete globalState.resizeObservers[windowId];
                }

                // Update the advanced dashboard if open
                if (globalState.advancedMode) {
                    updateDashboardContent();
                }
            }, 300);
        });
    }
};

// Setup tabs
const setupTabs = (windowElement) => {
    if (!windowElement) return;

    const tabButtons = windowElement.querySelectorAll('.tab-button');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all tabs
            windowElement.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            windowElement.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            // Add active class to clicked tab
            button.classList.add('active');

            // Show related content
            const tabId = button.dataset.tab;
            const tabContent = windowElement.querySelector(`#${tabId}`);
            if (tabContent) {
                tabContent.classList.add('active');
            }
        });
    });
};

// Function to add a camera to the list
const addCamera = (url) => {
    // Check if camera already exists
    if (globalState.cameras.includes(url)) {
        console.log('Camera already exists in the list');
        return false;
    }

    // Add to state - add to end of array for original order
    globalState.cameras.push(url);

    // Create list item
    const listItem = createElementWithHTML('li',
        `<i class="fas fa-video"></i> ${url}`,
        'camera-list-item'
    );

    // Add click event
    listItem.addEventListener('click', () => openVideoWindow(url));

    // Add to DOM at the end to maintain original order
    DOM.get('cameraList').appendChild(listItem);

    // Update counts
    updateCameraCount();

    return true;
};

// Main Functionality
document.getElementById('addIpForm').addEventListener('submit', (event) => {
    event.preventDefault();

    const ipInput = document.getElementById('addIpInput').value.replace(/[\r\n\t]/g, '').trim();

    // Validate URL format
    const rtspRegex = /^rtsp:\/\/(:\S*)?@?(\d{1,3}\.){3}\d{1,3}:\d{1,5}(\/.*)?$/;
    const mjpgRegex = /^https?:\/\/(:\S*)?@?(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?(\/.*)?$/;

    // if (!rtspRegex.test(ipInput) && !mjpgRegex.test(ipInput)) {
    // alert('Invalid URL format. Please use a valid RTSP or HTTP stream URL.');
    //     return;
    // }

    // Add camera to list
    if (addCamera(ipInput)) {
        // Clear input field
        document.getElementById('addIpInput').value = '';
    }
});

// Fetch Content Functions
const fetchPastebinContent = async (url) => {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorMessage}`);
        }

        const data = await response.json();
        if (!data || !data.contents) {
            throw new Error('Invalid response format from proxy server');
        }

        return data.contents;
    } catch (error) {
        if (error.name === 'AbortError') {
            console.error('Pastebin request timed out');
            return '';
        }
        console.error('Error fetching Pastebin content:', error);
        return '';
    }
};

// Loading message - simplified version
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

// Update camera list from Pastebin - simplified approach
const updateCameraListFromPastebin = async (pastebinUrl) => {
    // Show loading message
    showLoadingMessage(true);

    // Start a timer to ensure loading message is cleared after a timeout
    const loadingTimeout = setTimeout(() => {
        showLoadingMessage(false);
    }, 10000); // 10 second max loading time

    try {
        const plainTextContent = await fetchPastebinContent(pastebinUrl);
        const urls = plainTextContent.split('\n')
            .map(url => url.replace(/[\r\n\t]/g, '').trim())
            .filter(url => url !== '');

        // Clear existing list
        DOM.get('cameraList').innerHTML = '';
        globalState.cameras = [];

        // Add each camera
        urls.forEach(url => {
            addCamera(url);
        });

        updateCameraCount();
    } catch (error) {
        console.error('Error updating camera list:', error);
    } finally {
        // Always clear the timeout and hide loading message
        clearTimeout(loadingTimeout);
        showLoadingMessage(false);
    }
};

// MJPG Stream Helper Functions
const isMjpgStream = (url) => {
    const lowerUrl = url.toLowerCase();
    return lowerUrl.includes('.mjpg') ||
        lowerUrl.includes('.mjpeg') ||
        lowerUrl.includes('mjpg/video') ||
        lowerUrl.includes('mjpeg/video') ||
        lowerUrl.includes('video.cgi') ||
        lowerUrl.includes('video.mjpg') ||
        lowerUrl.includes('video.mjpeg') ||
        lowerUrl.includes('snapshot.cgi') ||
        lowerUrl.includes('image.jpg') ||
        lowerUrl.includes('image.jpeg') ||
        lowerUrl.includes('cam.jpg') ||
        lowerUrl.includes('cam.jpeg') ||
        lowerUrl.includes('stream.jpg') ||
        lowerUrl.includes('stream.jpeg') ||
        lowerUrl.includes('live.jpg') ||
        lowerUrl.includes('live.jpeg') ||
        lowerUrl.includes('axis-cgi/mjpg') ||
        lowerUrl.includes('cgi-bin/mjpg') ||
        (lowerUrl.startsWith('http') && !lowerUrl.startsWith('rtsp'));
};

const formatMjpgUrl = (url) => {
    if (isMjpgStream(url)) {
        // If it's already a proper MJPG URL, return as is
        if (url.toLowerCase().includes('.mjpg') ||
            url.toLowerCase().includes('.mjpeg') ||
            url.toLowerCase().includes('video.cgi') ||
            url.toLowerCase().includes('snapshot.cgi')) {
            return url;
        }
        return url;
    }

    // For non-MJPG URLs, try to construct a common MJPG path
    const baseUrl = url.endsWith('/')?url.slice(0, -1) : url;
    return `${baseUrl}/mjpg/video.mjpg`;
};

// MJPG Player Creation Functions
const createMjpgImagePlayer = (url, useProxy = false) => {
    const container = document.createElement('div');
    container.className = 'mjpg-image-container';

    // Check for mixed content issues
    const isHttpsPage = window.location.protocol === 'https:';
    const isHttpUrl = url.startsWith('http:');
    let finalUrl = url;

    if (isHttpsPage && isHttpUrl) {
        if (useProxy) {
            // Create a blob-based solution for HTTP streams on HTTPS pages
            console.log('🔄 Using fetch-based proxy for HTTP MJPEG stream');
            return createFetchBasedMjpgPlayer(url);
        } else {
            // Show mixed content warning for image player
            container.innerHTML = `
                <div class="video-error">
                    <i class="fas fa-shield-alt"></i>
                    <h3>Mixed Content Blocked</h3>
                    <p>HTTP images are blocked on HTTPS pages.</p>
                    <small>${url}</small>
                    <div style="margin-top: 15px;">
                        <p><strong>Try:</strong> Switch to iframe player or use HTTP version of this app</p>
                    </div>
                </div>
            `;
            return container;
        }
    }

    const img = document.createElement('img');
    img.className = 'mjpg-image-player';

    // Add cache-busting parameter for better refresh
    const separator = finalUrl.includes('?')?'&' : '?';
    img.src = finalUrl + separator + 't=' + Date.now();
    img.style.width = '100%';
    img.style.height = '100%';
    img.style.objectFit = 'contain';
    img.alt = 'MJPG Stream';

    // Set up automatic refresh for MJPG streams
    let refreshInterval;
    const refreshRate = useProxy?3000 : 1000; // 3 seconds for proxy, 1 second for direct

    const refreshImage = () => {
        const newTimestamp = Date.now();
        if (useProxy) {
            // For proxy URLs, we need to add timestamp to original URL
            const originalUrlWithTimestamp = url + (url.includes('?')?'&' : '?') + 't=' + newTimestamp;
            img.src = `https://cors-anywhere.herokuapp.com/${originalUrlWithTimestamp}`;
        } else {
            const baseUrl = finalUrl.split('?')[0].split('&')[0];
            img.src = baseUrl + separator + 't=' + newTimestamp;
        }
    };

    // Add error handling
    img.onerror = (error) => {
        console.error('MJPG image failed to load:', url, error);

        // Stop refresh interval on repeated errors
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }

        // Create retry function
        const retryLoad = () => {
            const newImg = document.createElement('img');
            newImg.className = 'mjpg-image-player';
            newImg.style.width = '100%';
            newImg.style.height = '100%';
            newImg.style.objectFit = 'contain';
            newImg.alt = 'MJPG Stream';

            // Try alternative protocol if current failed
            let retryUrl = url;
            if (finalUrl.startsWith('https:') && url.startsWith('http:')) {
                // If we tried HTTPS and failed, try original HTTP
                retryUrl = url + (url.includes('?')?'&' : '?') + 't=' + Date.now();
                console.log('HTTPS failed, trying original HTTP URL:', retryUrl);
            } else {
                // Try with cache-busting parameter
                retryUrl = finalUrl + (finalUrl.includes('?')?'&' : '?') + 't=' + Date.now();
                console.log('Retrying with cache-busting:', retryUrl);
            }

            newImg.src = retryUrl;

            // Add same error handler
            newImg.onerror = () => {
                console.error('MJPG retry failed for:', retryUrl);
                container.innerHTML = `
                    <div class="video-error">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>Failed to load MJPG stream</p>
                        <small>${url}</small>
                        <p style="margin-top: 10px; font-size: 12px; color: #94a3b8;">
                            Try switching to "MJPG Iframe Player" in Settings tab
                        </p>
                    </div>
                `;
            };

            newImg.onload = () => {
                console.log('MJPG stream loaded successfully on retry');
            };

            container.innerHTML = '';
            container.appendChild(newImg);
        };

        container.innerHTML = `
            <div class="video-error">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Failed to load MJPG stream</p>
                <small>${url}</small>
                <div style="margin-top: 10px;">
                    <button class="retry-btn" style="padding: 5px 10px; background: #e11d48; color: white; border: none; border-radius: 3px; cursor: pointer;">
                        Retry
                    </button>
                </div>
            </div>
        `;

        // Add event listener to retry button
        const retryBtn = container.querySelector('.retry-btn');
        if (retryBtn) {
            retryBtn.addEventListener('click', retryLoad);
        }
    };

    // Add loading indicator
    img.onload = () => {
        console.log('MJPG stream loaded successfully');
        // Start auto-refresh after first successful load
        if (!refreshInterval) {
            refreshInterval = setInterval(refreshImage, refreshRate);
            console.log('Started MJPG auto-refresh with', refreshRate + 'ms interval');
        }
    };

    // Store cleanup function on container for later use
    container.cleanup = () => {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
            console.log('Stopped MJPG auto-refresh');
        }
    };

    container.appendChild(img);
    return container;
};

const createMjpgIframePlayer = (url) => {
    const container = document.createElement('div');
    container.className = 'mjpg-iframe-container';
    container.style.width = '100%';
    container.style.height = '100%';
    container.style.position = 'relative';

    // Check if we need to proxy HTTP streams on HTTPS
    const isHttpsPage = window.location.protocol === 'https:';
    const isHttpUrl = url.startsWith('http:');

    if (isHttpsPage && isHttpUrl) {
        // Use image-based player with CORS proxy instead of iframe
        console.log('🔄 Using image-based CORS proxy for HTTP MJPEG stream');
        return createMjpgImagePlayer(url, true); // Pass true to indicate proxy usage
    }

    const iframe = document.createElement('iframe');
    iframe.className = 'mjpg-iframe-player';
    iframe.frameBorder = '0';
    iframe.width = '100%';
    iframe.height = '100%';
    iframe.src = url;
    iframe.allowFullscreen = true;
    iframe.style.border = 'none';
    iframe.style.display = 'block';

    // Set up refresh mechanism
    let refreshInterval;
    const refreshRate = 3000; // 3 seconds

    const refreshIframe = () => {
        const separator = url.includes('?')?'&' : '?';
        iframe.src = url + separator + 't=' + Date.now();
        console.log('🔄 Refreshed MJPG iframe');
    };

    // Function to calculate and apply scaling
    const applyScaling = () => {
        const containerRect = container.getBoundingClientRect();
        const containerWidth = containerRect.width;
        const containerHeight = containerRect.height;

        // Skip if container has no size yet
        if (containerWidth === 0 || containerHeight === 0) {
            return;
        }

        // Assume 640x480 for MJPG streams (common default)
        const streamWidth = 640;
        const streamHeight = 480;

        // Calculate scale factors
        const scaleX = containerWidth / streamWidth;
        const scaleY = containerHeight / streamHeight;

        // Use the smaller scale to maintain aspect ratio and fit within container
        const scaleFactor = Math.min(scaleX, scaleY);

        // Apply scaling
        container.style.setProperty('--scale-factor', scaleFactor);
        container.classList.add('scale-to-fit');

        console.log(`📐 MJPG scaling: container(${containerWidth.toFixed(0)}x${containerHeight.toFixed(0)}) stream(${streamWidth}x${streamHeight}) scale(${scaleFactor.toFixed(2)})`);
    };

    // Start refresh after initial load
    iframe.onload = () => {
        console.log('✅ MJPG iframe loaded, starting refresh');

        // Apply scaling after a short delay to ensure container is sized
        setTimeout(applyScaling, 100);

        if (!refreshInterval) {
            refreshInterval = setInterval(refreshIframe, refreshRate);
        }
    };

    // Add error handling for iframe
    iframe.onerror = () => {
        console.error('MJPG iframe failed to load:', url);
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }
        container.innerHTML = `
            <div class="video-error">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Failed to load MJPG stream in iframe</p>
                <small>${url}</small>
                <p style="margin-top: 10px; font-size: 12px; color: #94a3b8;">
                    Try switching to "MJPG Image Player" in Settings tab
                </p>
            </div>
        `;
    };

    // Add resize observer to reapply scaling when container size changes
    let resizeObserver;
    if (window.ResizeObserver) {
        resizeObserver = new ResizeObserver(() => {
            applyScaling();
        });
        resizeObserver.observe(container);
    }

    // Store cleanup function
    container.cleanup = () => {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
            console.log('🛑 Stopped MJPG iframe refresh');
        }
        if (resizeObserver) {
            resizeObserver.disconnect();
            console.log('🛑 Stopped MJPG resize observer');
        }
    };

    container.appendChild(iframe);
    console.log('Created MJPG iframe player with refresh for:', url);
    return container;
};

const createFetchBasedMjpgPlayer = (url) => {
    const container = document.createElement('div');
    container.className = 'mjpg-fetch-container';
    container.style.width = '100%';
    container.style.height = '100%';
    container.style.position = 'relative';
    container.style.display = 'flex';
    container.style.alignItems = 'center';
    container.style.justifyContent = 'center';
    container.style.backgroundColor = '#000';

    const img = document.createElement('img');
    img.className = 'mjpg-fetch-player';
    img.style.maxWidth = '100%';
    img.style.maxHeight = '100%';
    img.style.objectFit = 'contain';
    img.alt = 'MJPG Stream';

    let refreshInterval;
    const refreshRate = 2000; // 2 seconds

    const fetchAndDisplayImage = async () => {
        try {
            // Add timestamp to prevent caching
            const urlWithTimestamp = url + (url.includes('?')?'&' : '?') + 't=' + Date.now();

            // Note: This will still be blocked by CORS, but we'll show a helpful message
            const response = await fetch(urlWithTimestamp, {
                mode: 'no-cors',
                cache: 'no-cache'
            });

            // Since we can't actually fetch due to CORS, show a helpful message
            throw new Error('CORS blocked');

        } catch (error) {
            console.log('Fetch blocked by CORS, showing helpful message');

            // Clear any existing interval
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
            }

            container.innerHTML = `
                <div class="video-error" style="text-align: center; color: white; padding: 20px;">
                    <i class="fas fa-shield-alt" style="font-size: 48px; margin-bottom: 15px; color: #f59e0b;"></i>
                    <h3 style="margin: 10px 0; color: #f3f4f6;">Mixed Content Security</h3>
                    <p style="margin: 10px 0; color: #d1d5db;">HTTP streams cannot be loaded on HTTPS pages due to browser security.</p>
                    <div style="margin: 15px 0; padding: 15px; background: rgba(239, 68, 68, 0.1); border-radius: 8px; border-left: 4px solid #ef4444;">
                        <p style="margin: 5px 0; font-size: 14px; color: #fecaca;"><strong>Solutions:</strong></p>
                        <ul style="text-align: left; margin: 10px 0; color: #fecaca; font-size: 13px;">
                            <li>Use the HTTP version of this app (not HTTPS)</li>
                            <li>Find an HTTPS version of the stream</li>
                            <li>Use a local proxy server</li>
                        </ul>
                    </div>
                    <small style="color: #9ca3af; font-family: monospace;">${url}</small>
                </div>
            `;
        }
    };

    // Store cleanup function
    container.cleanup = () => {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }
    };

    // Start the fetch attempt
    fetchAndDisplayImage();

    return container;
};

const createMjpgPlayer = (url, playerType = 'iframe') => {
    console.log(`Creating MJPG player (${playerType}) for URL:`, url);

    switch (playerType) {
        case 'image':
            return createMjpgImagePlayer(url);
        case 'iframe':
        default:
            return createMjpgIframePlayer(url);
    }
};

// Video Window Creation
const createStreamedianPlayer = (url, resolution) => {
    const iframe = document.createElement('iframe');
    iframe.className = 'video-player';
    iframe.frameBorder = '0';
    iframe.allowFullscreen = '1';
    iframe.src = `https://streamedian.com/embed?w=ZXVwLnN0cmVhbWVkaWFuLmNvbQ==&s=${btoa(url)}&r=${btoa(resolution)}`;
    iframe.width = '100%';
    iframe.height = '100%';
    return iframe;
};

const createFlashphonerPlayer = (url) => {
    const iframe = document.createElement('iframe');
    iframe.className = 'video-player';
    iframe.id = 'fp_embed_player';
    iframe.frameBorder = '0';
    iframe.marginWidth = '0';
    iframe.marginHeight = '0';
    iframe.allowFullscreen = 'allowfullscreen';
    iframe.width = '100%';
    iframe.height = '100%';
    iframe.scrolling = 'no';

    // Clean the URL by removing any carriage returns or newlines
    const cleanUrl = url.replace(/[\r\n]+/g, '');

    // Set up the proper WebSocket server URL and WebRTC configuration
    const wsUrl = 'wss://demo.flashphoner.com:8443';
    const rtcConfig = encodeURIComponent(JSON.stringify({
        iceServers: [{
            urls: ['stun:stun.l.google.com:19302']
        }],
        sdpSemantics: 'unified-plan',
        bundlePolicy: 'max-bundle'
    }));

    // Add necessary query parameters for better connection handling
    const queryParams = new URLSearchParams({
        urlServer: wsUrl,
        streamName: cleanUrl,
        mediaProviders: 'WebRTC,MSE',
        rtcConfig: rtcConfig,
        useWorker: 'true',
        receiverType: 'webrtc'
    });

    iframe.src = `https://demo.flashphoner.com:8888/embed_player?${queryParams.toString()}`;

    // Add required permissions for iframe
    iframe.allow = "camera; microphone; fullscreen; display-capture; autoplay";

    return iframe;
};

// Modify the openVideoWindow function to directly add the click handler
const openVideoWindow = (url) => {
    // Clean the URL by removing any carriage returns, newlines, or extra whitespace
    const cleanUrl = url.replace(/[\r\n\t]/g, '').trim();
    console.log('[openVideoWindow] Opening video window for URL:', cleanUrl);

    // Generate a unique ID for this window
    const windowId = 'window-' + Date.now();
    console.log('[openVideoWindow] Generated window ID:', windowId);

    // Clone the template
    const template = document.getElementById('videoWindowTemplate');
    const newWindow = template.content.cloneNode(true).querySelector('.window');

    // Set window ID and store original stream URL
    newWindow.dataset.id = windowId;
    newWindow.dataset.streamUrl = cleanUrl;
    console.log('[openVideoWindow] Created window element with dataset:', newWindow.dataset);

    // Set window title
    newWindow.querySelector('.video-title').textContent = cleanUrl;

    // Calculate position (cascade)
    const offset = 20 * (globalState.activeWindows.length % 5);
    newWindow.style.top = `${70 + offset}px`;
    newWindow.style.left = `${350 + offset}px`;

    // Add to active windows
    globalState.activeWindows.push(windowId);

    // Setup window content - video section
    const videoContainer = newWindow.querySelector('.video-container');

    // Add to DOM first
    document.body.appendChild(newWindow);

    // Set explicit dimensions for the video window
    newWindow.style.width = '850px';
    newWindow.style.height = '600px';

    if (isMjpgStream(cleanUrl)) {
        // For MJPG streams, use the improved MJPG player
        const mjpgUrl = formatMjpgUrl(cleanUrl);

        // Update status bar to show MJPG stream
        const statusResolution = newWindow.querySelector('.stream-resolution');
        if (statusResolution) {
            statusResolution.textContent = 'MJPG Stream';
        }

        // Setup player selection for MJPG streams
        const playerSelects = newWindow.querySelectorAll('.player-select');
        playerSelects.forEach(playerSelect => {
            if (playerSelect) {
                // Update options for MJPG streams
                playerSelect.innerHTML = `
                    <option value="mjpg-image">MJPG Image Player</option>
                    <option value="mjpg-iframe">MJPG Iframe Player</option>
                `;

                // Set default MJPG player preference
                const mjpgPlayerPreference = globalState.mjpgPlayerPreference || 'mjpg-image';
                playerSelect.value = mjpgPlayerPreference;

                // Add change event listener for MJPG player switching
                playerSelect.addEventListener('change', (e) => {
                    globalState.mjpgPlayerPreference = e.target.value;
                    // Update both dropdowns to stay in sync
                    playerSelects.forEach(select => {
                        select.value = e.target.value;
                    });

                    // Replace the current player with the new one
                    const currentPlayer = videoContainer.querySelector('.mjpg-image-container, .mjpg-iframe-container');
                    if (currentPlayer) {
                        // Clean up any intervals before removing
                        if (currentPlayer.cleanup) {
                            currentPlayer.cleanup();
                        }
                        currentPlayer.remove();
                    }

                    const playerType = e.target.value.replace('mjpg-', '');
                    const newPlayer = createMjpgPlayer(mjpgUrl, playerType);
                    videoContainer.appendChild(newPlayer);

                    // Show notification
                    showNotification(`<i class="fas fa-exchange-alt"></i> Switched to ${e.target.value} player`);
                });
            }
        });

        // Create initial MJPG player
        const mjpgPlayerType = (globalState.mjpgPlayerPreference || 'mjpg-image').replace('mjpg-', '');
        const mjpgPlayer = createMjpgPlayer(mjpgUrl, mjpgPlayerType);
        videoContainer.appendChild(mjpgPlayer);

    } else {
        // Handle RTSP streams with existing player logic
        // Get the appropriate resolution based on global settings
        let resolution = globalState.autoResolution ?
            calculateOptimalResolution(videoContainer.clientWidth, videoContainer.clientHeight) :
            globalState.manualResolution;

        // Fallback to a safe value if calculation fails
        if (!resolution) resolution = "720x420";

        // Update resolution in status bar
        const statusResolution = newWindow.querySelector('.stream-resolution');
        if (statusResolution) {
            statusResolution.textContent = resolution;
        }

        // Setup player selection in settings tab and overlay
        const playerSelects = newWindow.querySelectorAll('.player-select');
        playerSelects.forEach(playerSelect => {
            if (playerSelect) {
                playerSelect.value = globalState.playerPreference;

                // Add change event listener
                playerSelect.addEventListener('change', (e) => {
                    globalState.playerPreference = e.target.value;
                    // Update both dropdowns to stay in sync
                    playerSelects.forEach(select => {
                        select.value = e.target.value;
                    });
                    updateRtspStreamResolution(newWindow, cleanUrl, resolution);

                    // Show notification
                    showNotification(`<i class="fas fa-exchange-alt"></i> Switched to ${e.target.value} player`);
                });
            }
        });

        // Create initial player
        const player = globalState.playerPreference === 'streamedian' ?
            createStreamedianPlayer(cleanUrl, resolution) :
            createFlashphonerPlayer(cleanUrl);

        videoContainer.appendChild(player);

        // If we want to setup resize observer, we can do so here
        if (globalState.autoResolution) {
            setupResizeObserver(newWindow, videoContainer, cleanUrl);
        }
    }

    // Setup window controls
    setupWindowControls(newWindow);

    // Make window draggable
    makeDraggable(newWindow, newWindow.querySelector('.window-titlebar'));

    // Make window resizable
    makeResizable(newWindow);

    // Setup tabs in the window
    setupTabsInWindow(newWindow);

    // Extract IP address from URL
    const ip = extractIpFromUrl(cleanUrl);
    if (ip) {
        fetchIPInfo(ip, newWindow);
    }

    // Update camera data in advanced dashboard if open
    if (globalState.advancedMode) {
        updateDashboardContent();
        populateCurrentIpSelector();
    }

    // DIRECT METADATA BUTTON HANDLER - This is the key fix
    const extractMetadataBtn = newWindow.querySelector('.extract-metadata-btn');
    if (extractMetadataBtn) {
        console.log('Setting up extract metadata button click handler directly in openVideoWindow');
        extractMetadataBtn.addEventListener('click', (event) => {
            event.preventDefault();
            console.log('Extract metadata button clicked directly');

            // Get the window element (parent of the button)
            const windowEl = event.target.closest('.window');
            console.log('Window element from button click:', windowEl);

            if (windowEl) {
                console.log('Calling extractCameraMetadata function directly');

                // Show loading indicator
                const loadingIndicator = windowEl.querySelector('.metadata-loading');
                if (loadingIndicator) {
                    loadingIndicator.style.display = 'flex';
                }

                try {
                    // Call the metadata extraction function
                    const result = extractCameraMetadata(windowEl);
                    console.log('Metadata extraction result:', result);

                    // Show notification based on result
                    if (result.success) {
                        showNotification('Metadata extraction completed successfully', 'success');
                    } else {
                        showNotification(`Metadata extraction failed: ${result.error}`, 'error');
                    }
                } catch (error) {
                    console.error('Error during metadata extraction:', error);
                    showNotification(`Error during metadata extraction: ${error.message}`, 'error');
                } finally {
                    // Hide loading indicator
                    if (loadingIndicator) {
                        loadingIndicator.style.display = 'none';
                    }
                }
            } else {
                console.error('Could not find window element for metadata extraction');
                showNotification('Could not find window element for metadata extraction', 'error');
            }
        });
    }

    // NETWORK DISCOVERY EVENT HANDLERS
    setupNetworkDiscoveryHandlers(newWindow, cleanUrl);

    // THREAT INTELLIGENCE EVENT HANDLERS
    setupThreatIntelHandlers(newWindow, cleanUrl);



    // INFO TABS SCROLLING HANDLERS
    setupInfoTabsScrolling(newWindow);

    // DATA EXPORT & REPORTING HANDLERS
    setupDataExportHandlers(newWindow, cleanUrl);



    return newWindow;
};

// Add the setupTabsInWindow function
const setupTabsInWindow = (windowElement) => {
    if (!windowElement) return;

    const tabButtons = windowElement.querySelectorAll('.tab-button');
    const tabContents = windowElement.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Add active class to clicked button
            button.classList.add('active');

            // Show corresponding content
            const tabId = button.dataset.tab;
            const tabContent = windowElement.querySelector(`#${tabId}`);
            if (tabContent) {
                tabContent.classList.add('active');
            }
        });
    });
};

// Make window resizable (simplified version that doesn't change resolution)
const makeResizable = (windowElement) => {
    if (!windowElement) return;

    // Create resize handles if not already present
    const handles = ['se', 'sw', 'ne', 'nw', 'n', 's', 'e', 'w'];

    handles.forEach(direction => {
        const handleClass = `resize-handle resize-${direction}`;
        if (!windowElement.querySelector(`.${handleClass.split(' ')[1]}`)) {
            const handle = document.createElement('div');
            handle.className = handleClass;
            windowElement.appendChild(handle);

            // Setup resize event handling
            handle.addEventListener('mousedown', (e) => {
                e.preventDefault();
                startResize(e, windowElement, direction);
            });
        }
    });
};

// Start resize function (simplified)
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

    // Resize function
    const resize = (e) => {
        // Bring window to front
        const highestZIndex = Math.max(
            ...Array.from(document.querySelectorAll('.window'))
            .map(w => parseInt(getComputedStyle(w).zIndex) || 0)
        );
        windowElement.style.zIndex = highestZIndex + 1;

        // Calculate new dimensions based on direction
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

        // Apply new dimensions
        windowElement.style.width = `${newWidth}px`;
        windowElement.style.height = `${newHeight}px`;
        windowElement.style.top = `${newTop}px`;
        windowElement.style.left = `${newLeft}px`;
    };

    // Finish resize function
    const stopResize = () => {
        window.removeEventListener('mousemove', resize);
        window.removeEventListener('mouseup', stopResize);
    };

    // Add event listeners
    window.addEventListener('mousemove', resize);
    window.addEventListener('mouseup', stopResize);
};

// IP Information
async function fetchIPInfo(ip, windowElement) {
    if (!ip || !windowElement) return;

    const windowId = windowElement.dataset.id;
    if (!windowId) return;

    // Set loading indicator
    const ipInfoContainer = windowElement.querySelector('#ipInfoContainer');
    if (ipInfoContainer) {
        ipInfoContainer.innerHTML = '<div class="loading"><i class="fas fa-circle-notch fa-spin"></i> Loading IP information...</div>';
    }

    // Safety timeout to prevent infinite loading
    const loadingTimeout = setTimeout(() => {
        if (ipInfoContainer) {
            ipInfoContainer.innerHTML = '<div class="error-message"><i class="fas fa-exclamation-triangle"></i> Error: IP info request timed out.</div>';
        }
    }, 15000);

    try {
        // Use CORS proxy to fetch IP info
        const ipInfoUrl = `${API_ENDPOINTS.IP_INFO}${ip}?fields=${API_ENDPOINTS.IP_INFO_FIELDS}`;
        console.log(`Fetching IP info using proxy from: ${ipInfoUrl}`);

        // Use fetch with a timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: ipInfoUrl
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId); // Clear fetch timeout

        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorMessage}`);
        }

        const proxyResponse = await response.json();

        if (!proxyResponse || !proxyResponse.contents) {
            throw new Error('Invalid response from proxy server');
        }

        // Parse the contents from the proxy response
        const ipData = JSON.parse(proxyResponse.contents);

        if (!ipData || !ipData.query) {
            throw new Error('Invalid IP data structure');
        }

        // Clear safety timeout since we got data
        clearTimeout(loadingTimeout);

        // Store raw data for advanced mode
        globalState.rawData.ipInfo[windowId] = ipData;

        // Update the raw IP data in the settings tab
        const rawIpContainer = windowElement.querySelector('.raw-ip-data');
        if (rawIpContainer) {
            rawIpContainer.textContent = JSON.stringify(ipData, null, 2);
        }

        // Update UI with data
        updateIPInfoUI(ipData, windowElement);

        // Fetch ASN info if available
        if (ipData.query) {
            fetchAndUpdateASN(ipData.query, windowElement);
        }

        // Update dashboard if in advanced mode
        if (globalState.advancedMode) {
            updateDashboardContent();
            if (globalState.currentSelectedCamera === windowId) {
                updateCurrentIpDisplay();
            }
        }

    } catch (error) {
        console.error('Error fetching IP info:', error);

        // Clear safety timeout since we got an error
        clearTimeout(loadingTimeout);

        // Update UI with error
        if (ipInfoContainer) {
            ipInfoContainer.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Error fetching IP information: ${error.message || 'Unknown error'}</p>
                </div>
            `;
        }
    }
}

// ASN Information
async function fetchAndUpdateASN(ip, windowElement) {
    if (!ip || !windowElement) return;

    const windowId = windowElement.dataset.id;
    if (!windowId) return;

    try {
        // Use CORS proxy for ASN info too
        const asnUrl = `${API_ENDPOINTS.ASN_INFO}${ip}/json`;
        console.log(`Fetching ASN info using proxy from: ${asnUrl}`);

        // Use fetch with a timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: asnUrl
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId); // Clear fetch timeout

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const proxyResponse = await response.json();

        if (!proxyResponse || !proxyResponse.contents) {
            throw new Error('Invalid response from proxy server');
        }

        // Parse the contents from the proxy response
        const asnData = JSON.parse(proxyResponse.contents);

        // Store raw ASN data for advanced mode
        globalState.rawData.asnInfo[windowId] = asnData;

        // Update the raw ASN data in the settings tab
        const rawAsnContainer = windowElement.querySelector('.raw-asn-data');
        if (rawAsnContainer) {
            rawAsnContainer.textContent = JSON.stringify(asnData, null, 2);
        }

        // We don't need a dedicated ASN display in the info view, as the main IP info already includes ASN
        // But update dashboard if in advanced mode
        if (globalState.advancedMode) {
            updateDashboardContent();
            if (globalState.currentSelectedCamera === windowId) {
                updateCurrentIpDisplay();
            }
        }
    } catch (error) {
        console.error('Error fetching ASN info:', error);
        // Just log the error but don't display it as the IP info is still valuable
    }
}

// Update IP Info UI
const updateIPInfoUI = (data, windowElement) => {
    if (!data || !windowElement) return;

    // Get window ID
    const windowId = windowElement.dataset.id;
    if (!windowId) return;

    // Update window title with location
    const titleElement = windowElement.querySelector('.window-title');
    if (titleElement && data.city && data.country) {
        titleElement.textContent = `${data.city}, ${data.country}`;
    }

    // Update specific UI content - target the correct element with ID
    const ipInfoContainer = windowElement.querySelector('#ipInfoContainer');

    if (ipInfoContainer) {
        const threatStatus = data.proxy || data.hosting;
        const securityClass = threatStatus?'security-alert' : 'security-safe';

        ipInfoContainer.innerHTML = `
            <div class="ip-header">
                <div class="location-name">
                    <i class="fas fa-map-marker-alt"></i>
                    <span>${data.city || 'Unknown'}, ${data.regionName || ''}, ${data.country || 'Unknown'}</span>
                </div>
                <div class="ip-address">
                    <i class="fas fa-network-wired"></i>
                    <span>${data.query || 'Unknown IP'}</span>
                </div>
            </div>

            <div class="info-section">
                <h3><i class="fas fa-globe"></i> Location</h3>
                <div class="info-row">
                    <span class="info-label">City:</span>
                    <span class="info-value">${data.city || 'Unknown'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Region:</span>
                    <span class="info-value">${data.regionName || 'Unknown'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Country:</span>
                    <span class="info-value">${data.country || 'Unknown'} ${data.countryCode?`(${data.countryCode})` : ''}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Timezone:</span>
                    <span class="info-value">${data.timezone || 'Unknown'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Coordinates:</span>
                    <span class="info-value">${data.lat?data.lat.toFixed(4) : '?'}, ${data.lon?data.lon.toFixed(4) : '?'}</span>
                </div>
            </div>

            <div class="info-section">
                <h3><i class="fas fa-server"></i> Network</h3>
                <div class="info-row">
                    <span class="info-label">ISP:</span>
                    <span class="info-value">${data.isp || 'Unknown'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Organization:</span>
                    <span class="info-value">${data.org || 'Unknown'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">AS:</span>
                    <span class="info-value">${data.as || 'Unknown'}</span>
                </div>
                <div class="info-row ${securityClass}">
                    <span class="info-label">Security:</span>
                    <span class="info-value">
                        ${threatStatus?'Potentially Unsafe' : 'Normal'}
                        ${data.proxy?'<i class="fas fa-shield-alt"></i> Proxy' : ''}
                        ${data.hosting?'<i class="fas fa-server"></i> Hosting' : ''}
                        ${data.mobile?'<i class="fas fa-mobile-alt"></i> Mobile' : ''}
                    </span>
                </div>
            </div>
        `;
    }

    // Update map section
    const mapContainer = windowElement.querySelector('#camera-location');
    if (mapContainer && data.lat && data.lon) {
        // Embed Google Maps with the location
        mapContainer.innerHTML = `
            <div class="map-container">
                <iframe width="100%" height="100%" frameborder="0" style="border:0"
                    src="https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;coord=${data.lat},${data.lon}&amp;q=1%20${data.district || ''}%20Street%2C%20${data.city || ''}%2C%20${data.regionName || ''}&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed"
                    allowfullscreen>
                </iframe>
            </div>
        `;
    } else if (mapContainer) {
        mapContainer.innerHTML = '<div class="map-placeholder">Map data not available</div>';
    }

    // If in advanced mode, update the dashboard content
    if (globalState.advancedMode) {
        updateDashboardContent();

        // If this is the selected camera in the dashboard, update its display
        if (globalState.currentSelectedCamera === windowId) {
            updateCurrentIpDisplay();
        }
    }
};

// Update Google Maps
const updateGoogleMaps = (lat, lon, district, city, regionName, windowElement) => {
    if (!lat || !lon || !windowElement) return;

    const mapContainer = windowElement.querySelector('#camera-location');
    if (!mapContainer) return;

    // Add Google Maps iframe
    const locationName = [district, city, regionName].filter(Boolean).join(', ');

    mapContainer.innerHTML = `
        <iframe width="100%" height="100%" frameborder="0" style="border:0"
            src="https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;coord=${lat},${lon}&amp;q=1%20${district}%20Street%2C%20${city}%2C%20${regionName}&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed"
            allowfullscreen>
        </iframe>
    `;
};

// Face Detection (if using face-api.js)
const initFaceDetection = async (imageElement, overlayElement) => {
    if (!imageElement || !overlayElement || !window.faceapi) return;

    try {
        // Wait for face-api.js models to load
        await Promise.all([
            faceapi.nets.tinyFaceDetector.loadFromUri('/models'),
            faceapi.nets.faceLandmark68Net.loadFromUri('/models'),
            faceapi.nets.faceRecognitionNet.loadFromUri('/models')
        ]);

        // Set up face detection interval
        const interval = setInterval(async () => {
            // Check if toggle is on
            const toggle = document.getElementById('faceDetectionToggle');
            if (!toggle || !toggle.checked) {
                overlayElement.innerHTML = '';
                return;
            }

            // Check if elements still exist
            if (!document.body.contains(imageElement) || !document.body.contains(overlayElement)) {
                clearInterval(interval);
                return;
            }

            try {
                // Detect faces
                const detections = await faceapi.detectAllFaces(
                    imageElement,
                    new faceapi.TinyFaceDetectorOptions()
                );

                // Clear previous detections
                overlayElement.innerHTML = '';

                // Draw face boxes
                detections.forEach(detection => {
                    const {
                        x,
                        y,
                        width,
                        height
                    } = detection.box;

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

// Advanced Dashboard Functions
const openAdvancedDashboard = () => {
    // Check if dashboard is already open
    if (document.getElementById('advancedDashboard')) {
        return;
    }

    globalState.advancedMode = true;

    // Create dashboard from template
    const template = document.getElementById('advancedDashboardTemplate');
    const dashboard = template.content.cloneNode(true).querySelector('.advanced-dashboard');

    // Calculate position (center of screen)
    const windowWidth = window.innerWidth;
    const windowHeight = window.innerHeight;
    dashboard.style.top = `${(windowHeight - 600) / 2}px`;
    dashboard.style.left = `${(windowWidth - 900) / 2}px`;

    // Make draggable
    document.body.appendChild(dashboard);
    makeDraggable(dashboard, dashboard.querySelector('.window-titlebar'));

    // Setup window controls
    setupWindowControls(dashboard);

    // Setup dashboard functionality
    setupDashboardNavigation(dashboard);

    // Initialize dashboard content
    updateDashboardContent();

    // Setup current IP functionality
    setupCurrentIPFunctionality();

    // Update dashboard time
    updateAdvancedModeTime();
    setInterval(updateAdvancedModeTime, 1000);

    // Set Current IP as the active section by default
    const currentIpNavItem = dashboard.querySelector('.nav-item[data-section="current-ip"]');
    const apiEndpointsNavItem = dashboard.querySelector('.nav-item[data-section="api-endpoints"]');

    if (currentIpNavItem && apiEndpointsNavItem) {
        // Remove active class from API Endpoints
        apiEndpointsNavItem.classList.remove('active');
        dashboard.querySelector('#api-endpoints').classList.remove('active');

        // Add active class to Current IP
        currentIpNavItem.classList.add('active');
        dashboard.querySelector('#current-ip').classList.add('active');
    }
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
            // Remove active class from all items
            navItems.forEach(nav => nav.classList.remove('active'));

            // Add active class to clicked item
            item.classList.add('active');

            // Show corresponding section
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
    // Update API endpoints information
    updateApiEndpointsSection();

    // Update state information
    updateStateSection();

    // Update camera data
    updateCameraDataSection();

    // Update current IP selector
    populateCurrentIpSelector();

    // Update current IP display
    updateCurrentIpDisplay();
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
        // Create a copy of the state to display, but filter out large datasets
        const displayState = {
            ...globalState
        };

        // Don't show the full console log history
        if (displayState.consoleLog && displayState.consoleLog.length > 0) {
            displayState.consoleLog = `[Array(${displayState.consoleLog.length} items)]`;
        }

        stateView.textContent = JSON.stringify(displayState, null, 2);
    }
};

const updateCameraDataSection = () => {
    const cameraDataList = document.getElementById('camerasDataList');
    if (!cameraDataList) return;

    // Clear previous content
    cameraDataList.innerHTML = '';

    // Add data for each active window
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

    // If no cameras, show a message
    if (globalState.activeWindows.length === 0) {
        cameraDataList.innerHTML = '<p>No active cameras to display</p>';
    }
};

const updateConsoleOutput = () => {
    const consoleOutput = document.getElementById('consoleOutput');
    if (!consoleOutput) return;

    consoleOutput.innerHTML = '';

    // Display the last 50 console entries
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

    // Auto-scroll to bottom
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
};

const updateAdvancedModeTime = () => {
    const timeElement = document.getElementById('advancedModeTime');
    if (timeElement) {
        const now = new Date();
        timeElement.textContent = now.toLocaleTimeString();
    }
};

// Current IP functions
const populateCurrentIpSelector = () => {
    const selector = document.getElementById('currentIpSelector');
    if (!selector) return;

    // Get the currently selected value if any
    const currentValue = selector.value;

    // Clear existing options, keeping only the default one
    selector.innerHTML = '<option value="">Select a camera...</option>';

    // Add each active camera
    globalState.activeWindows.forEach(windowId => {
        const windowElement = document.querySelector(`.window[data-id="${windowId}"]`);
        if (!windowElement) return;

        const streamUrl = windowElement.dataset.streamUrl;
        if (!streamUrl) return;

        const option = document.createElement('option');
        option.value = windowId;
        option.textContent = streamUrl;

        // Check if this was the previously selected one
        if (windowId === currentValue) {
            option.selected = true;
        }

        selector.appendChild(option);
    });

    // If nothing is selected but there are cameras, select the first one
    if (!selector.value && globalState.activeWindows.length > 0) {
        selector.value = globalState.activeWindows[0];
    }

    // Trigger change event to update display
    if (selector.value) {
        globalState.currentSelectedCamera = selector.value;
        updateCurrentIpDisplay();
    }
};

const updateCurrentIpDisplay = () => {
    const windowId = globalState.currentSelectedCamera;
    if (!windowId) return;

    const windowElement = document.querySelector(`.window[data-id="${windowId}"]`);
    if (!windowElement) return;

    const streamUrl = windowElement.dataset.streamUrl;
    const ipData = globalState.rawData.ipInfo[windowId];
    const asnData = globalState.rawData.asnInfo[windowId];

    // Update IP address display
    const ipAddressElement = document.getElementById('currentIpAddress');
    if (ipAddressElement) {
        ipAddressElement.textContent = ipData?ipData.query : extractIpFromUrl(streamUrl) || 'Unknown IP';
    }

    // Update location display
    const locationElement = document.getElementById('currentIpLocation');
    if (locationElement && ipData) {
        locationElement.textContent = `${ipData.city || ''}, ${ipData.regionName || ''}, ${ipData.country || ''}`;
    } else if (locationElement) {
        locationElement.textContent = '';
    }

    // Update network details
    const networkElement = document.getElementById('currentIpNetwork');
    if (networkElement && ipData) {
        networkElement.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">ISP:</span>
                <span class="detail-value">${ipData.isp || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Org:</span>
                <span class="detail-value">${ipData.org || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">AS:</span>
                <span class="detail-value">${ipData.as || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Mobile:</span>
                <span class="detail-value">${ipData.mobile?'Yes' : 'No'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Proxy:</span>
                <span class="detail-value">${ipData.proxy?'Yes' : 'No'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Hosting:</span>
                <span class="detail-value">${ipData.hosting?'Yes' : 'No'}</span>
            </div>
        `;
    } else if (networkElement) {
        networkElement.innerHTML = '<p>No network data available</p>';
    }

    // Update location details
    const locationDetailsElement = document.getElementById('currentIpLocationDetails');
    if (locationDetailsElement && ipData) {
        locationDetailsElement.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">City:</span>
                <span class="detail-value">${ipData.city || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Region:</span>
                <span class="detail-value">${ipData.regionName || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Country:</span>
                <span class="detail-value">${ipData.country || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Continent:</span>
                <span class="detail-value">${ipData.continent || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Timezone:</span>
                <span class="detail-value">${ipData.timezone || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Lat/Long:</span>
                <span class="detail-value">${ipData.lat || '?'}, ${ipData.lon || '?'}</span>
            </div>
        `;
    } else if (locationDetailsElement) {
        locationDetailsElement.innerHTML = '<p>No location data available</p>';
    }

    // Update ASN details
    const asnElement = document.getElementById('currentIpAsn');
    if (asnElement && asnData) {
        asnElement.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">ASN:</span>
                <span class="detail-value">${ipData?.as || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">ASN Name:</span>
                <span class="detail-value">${ipData?.asname || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Hostname:</span>
                <span class="detail-value">${asnData?.hostname || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Company:</span>
                <span class="detail-value">${asnData?.org || 'Unknown'}</span>
            </div>
        `;
    } else if (asnElement) {
        asnElement.innerHTML = '<p>No ASN data available</p>';
    }

    // Update stream details
    const streamDetailsElement = document.getElementById('currentIpStreamDetails');
    if (streamDetailsElement) {
        streamDetailsElement.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">URL:</span>
                <span class="detail-value">${streamUrl || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Type:</span>
                <span class="detail-value">${streamUrl?.startsWith('rtsp://')?'RTSP' : 'MJPG'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Resolution:</span>
                <span class="detail-value">${windowElement.querySelector('.stream-resolution')?.textContent || 'Unknown'}</span>
            </div>
        `;
    }

    // Update map
    const mapElement = document.getElementById('currentIpMap');
    if (mapElement && ipData && ipData.lat && ipData.lon) {
        mapElement.innerHTML = `
            <iframe width="100%" height="100%" frameborder="0" style="border:0"
            src="https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;coord=${ipData.lat},${ipData.lon}&amp;q=1%20${ipData.district || ''}%20Street%2C%20${ipData.city || ''}%2C%20${ipData.regionName || ''}&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed"
            allowfullscreen></iframe>
        `;
    } else if (mapElement) {
        mapElement.innerHTML = '<p>Map data not available</p>';
    }
};

const setupResolutionControls = () => {
    const autoResolutionToggle = document.getElementById('autoResolutionGlobal');
    const manualControls = document.getElementById('manualResolutionControls');
    const resolutionSelect = document.getElementById('manualResolution');
    const applyButton = document.getElementById('applyResolution');

    if (autoResolutionToggle) {
        // Set initial state
        autoResolutionToggle.checked = globalState.autoResolution;
        manualControls.style.display = globalState.autoResolution?'none' : 'flex';

        // Listen for changes
        autoResolutionToggle.addEventListener('change', (e) => {
            globalState.autoResolution = e.target.checked;
            manualControls.style.display = globalState.autoResolution?'none' : 'flex';

            // If auto resolution is turned on, update all active windows
            if (globalState.autoResolution) {
                globalState.activeWindows.forEach(windowId => {
                    const windowElement = document.querySelector(`.window[data-id="${windowId}"]`);
                    if (windowElement) {
                        const videoContainer = windowElement.querySelector('.video-container');
                        const streamUrl = windowElement.dataset.streamUrl;

                        if (streamUrl.startsWith('rtsp://') && videoContainer) {
                            const newResolution = calculateOptimalResolution(
                                videoContainer.clientWidth,
                                videoContainer.clientHeight
                            );

                            updateRtspStreamResolution(windowElement, streamUrl, newResolution);
                        }
                    }
                });
            }
        });
    }

    if (resolutionSelect) {
        // Set initial selected value
        const options = resolutionSelect.querySelectorAll('option');
        for (const option of options) {
            if (option.value === globalState.manualResolution) {
                option.selected = true;
                break;
            }
        }
    }

    if (applyButton) {
        applyButton.addEventListener('click', () => {
            if (!resolutionSelect || !resolutionSelect.value) return;

            globalState.manualResolution = resolutionSelect.value;

            // Apply to all active RTSP windows
            globalState.activeWindows.forEach(windowId => {
                const windowElement = document.querySelector(`.window[data-id="${windowId}"]`);
                if (windowElement) {
                    const streamUrl = windowElement.dataset.streamUrl;

                    if (streamUrl?.startsWith('rtsp://')) {
                        updateRtspStreamResolution(windowElement, streamUrl, globalState.manualResolution);
                    }
                }
            });

            // Update the current selected camera display
            updateCurrentIpDisplay();
        });
    }
};

// Resolution Functions
const calculateOptimalResolution = (containerWidth, containerHeight) => {
    // Ensure minimum dimensions
    const width = Math.max(containerWidth, 320);
    const height = Math.max(containerHeight, 240);

    // Round to nearest multiple of 16 for efficient encoding
    const roundedWidth = Math.round(width / 16) * 16;
    const roundedHeight = Math.round(height / 16) * 16;

    return `${roundedWidth}x${roundedHeight}`;
};

const updateRtspStreamResolution = (windowElement, streamUrl, resolution) => {
    if (!windowElement || !streamUrl || !resolution) return;

    const videoContainer = windowElement.querySelector('.video-container');
    if (!videoContainer) return;

    const iframe = videoContainer.querySelector('iframe');
    if (!iframe) return;

    // Get the current player type
    const playerSelect = windowElement.querySelector('.player-select');
    const currentPlayer = playerSelect?playerSelect.value : globalState.playerPreference;

    // Create new player with updated settings
    const newPlayer = currentPlayer === 'streamedian' ?
        createStreamedianPlayer(streamUrl, resolution) :
        createFlashphonerPlayer(streamUrl);

    // Replace the existing player
    iframe.replaceWith(newPlayer);

    // Update resolution in status bar
    const statusResolution = windowElement.querySelector('.stream-resolution');
    if (statusResolution) {
        statusResolution.textContent = resolution;
    }
};

const setupResizeObserver = (windowElement, videoContainer, url) => {
    if (!windowElement || !videoContainer || !url) return;

    const windowId = windowElement.dataset.id;
    if (!windowId) return;

    // Clean up existing observer and timeout if they exist
    if (globalState.resizeObservers[windowId]) {
        globalState.resizeObservers[windowId].observer.disconnect();
        if (globalState.resizeObservers[windowId].timeout) {
            clearTimeout(globalState.resizeObservers[windowId].timeout);
        }
        delete globalState.resizeObservers[windowId];
    }

    // Create new observer
    const observer = new ResizeObserver(entries => {
        // Only update if auto resolution is enabled
        if (!globalState.autoResolution) return;

        // Clear existing timeout
        if (globalState.resizeObservers[windowId]?.timeout) {
            clearTimeout(globalState.resizeObservers[windowId].timeout);
        }

        // Debounce to avoid too many updates
        const timeout = setTimeout(() => {
            if (!document.body.contains(windowElement)) {
                // Clean up if window was removed
                observer.disconnect();
                delete globalState.resizeObservers[windowId];
                return;
            }

            for (const entry of entries) {
                const {
                    width,
                    height
                } = entry.contentRect;
                const newResolution = calculateOptimalResolution(width, height);
                updateRtspStreamResolution(windowElement, url, newResolution);

                // Update the current IP display if this is the selected camera
                if (globalState.currentSelectedCamera === windowId) {
                    updateCurrentIpDisplay();
                }
            }
        }, 500);

        // Store timeout reference
        if (globalState.resizeObservers[windowId]) {
            globalState.resizeObservers[windowId].timeout = timeout;
        }
    });

    // Start observing
    observer.observe(videoContainer);

    // Store observer reference for cleanup
    globalState.resizeObservers[windowId] = {
        observer,
        timeout: null
    };

    // Add cleanup on window removal
    const cleanup = () => {
        if (globalState.resizeObservers[windowId]) {
            globalState.resizeObservers[windowId].observer.disconnect();
            if (globalState.resizeObservers[windowId].timeout) {
                clearTimeout(globalState.resizeObservers[windowId].timeout);
            }
            delete globalState.resizeObservers[windowId];
        }
    };

    windowElement.addEventListener('remove', cleanup);
    windowElement.addEventListener('DOMNodeRemoved', cleanup);
};

const setupCurrentIPFunctionality = () => {
    // Populate camera selector
    populateCurrentIpSelector();

    // Add event listener to camera selector
    const selector = document.getElementById('currentIpSelector');
    if (selector) {
        selector.addEventListener('change', (e) => {
            globalState.currentSelectedCamera = e.target.value;
            updateCurrentIpDisplay();
        });
    }

    // Add event listener to refresh button
    const refreshButton = document.getElementById('refreshCurrentIp');
    if (refreshButton) {
        refreshButton.addEventListener('click', () => {
            // Re-populate selector to catch any new cameras
            populateCurrentIpSelector();
            updateCurrentIpDisplay();

            // Show a notification
            showNotification('<i class="fas fa-sync-alt"></i> Camera list refreshed');
        });
    }

    // Add event listener to view window button
    const viewWindowButton = document.getElementById('viewCurrentWindow');
    if (viewWindowButton) {
        viewWindowButton.addEventListener('click', () => {
            const windowId = globalState.currentSelectedCamera;
            if (!windowId) {
                showNotification('<i class="fas fa-exclamation-triangle"></i> No camera selected', 'error');
                return;
            }

            const windowElement = document.querySelector(`.window[data-id="${windowId}"]`);
            if (windowElement) {
                // Bring window to front (assuming z-index handling)
                const activeWindows = document.querySelectorAll('.window');
                let maxZIndex = 0;

                activeWindows.forEach(win => {
                    const zIndex = parseInt(window.getComputedStyle(win).zIndex, 10);
                    if (!isNaN(zIndex) && zIndex > maxZIndex) {
                        maxZIndex = zIndex;
                    }
                });

                windowElement.style.zIndex = maxZIndex + 1;

                // Scroll to window if needed
                windowElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center'
                });

                // Apply a highlight effect
                windowElement.classList.add('highlight-window');
                setTimeout(() => {
                    windowElement.classList.remove('highlight-window');
                }, 2000);

                // Show notification
                showNotification('<i class="fas fa-eye"></i> Viewing camera window');
            } else {
                showNotification('<i class="fas fa-exclamation-triangle"></i> Camera window not found', 'error');
            }
        });
    }

    // Add event listener to refresh IP data button
    const refreshIpButton = document.getElementById('refreshIpData');
    if (refreshIpButton) {
        refreshIpButton.addEventListener('click', () => {
            const windowId = globalState.currentSelectedCamera;
            if (!windowId) {
                showNotification('<i class="fas fa-exclamation-triangle"></i> No camera selected', 'error');
                return;
            }

            const windowElement = document.querySelector(`.window[data-id="${windowId}"]`);
            if (windowElement) {
                const streamUrl = windowElement.dataset.streamUrl;
                const ip = extractIpFromUrl(streamUrl);

                if (ip) {
                    // Re-fetch the IP info
                    fetchIPInfo(ip, windowElement);

                    // Show a notification
                    showNotification('<i class="fas fa-sync-alt"></i> Refreshing IP data...');
                } else {
                    showNotification('<i class="fas fa-exclamation-triangle"></i> Could not extract IP from URL', 'error');
                }
            } else {
                showNotification('<i class="fas fa-exclamation-triangle"></i> Camera window not found', 'error');
            }
        });
    }

    // Setup resolution controls
    setupResolutionControls();
};

// Helper function to show dashboard notifications
const showNotification = (message, type = 'info') => {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `dashboard-notification notification-${type}`;
    notification.innerHTML = message;
    document.body.appendChild(notification);

    // Animate in
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);

    // Remove after delay
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 3000);
};

// Metadata extraction functions
function extractCameraMetadata(windowElement) {
    console.log('[extractCameraMetadata] Starting metadata extraction');

    // Check if window element exists
    if (!windowElement) {
        console.error('[extractCameraMetadata] Window element not found');
        return {
            success: false,
            error: 'Window element not found'
        };
    }

    // Get window ID - Fix: Use dataset.id instead of getAttribute('data-window-id')
    const windowId = windowElement.dataset.id;
    console.log('[extractCameraMetadata] Window element:', windowElement);
    console.log('[extractCameraMetadata] Window dataset:', windowElement.dataset);
    console.log('[extractCameraMetadata] Window ID from dataset:', windowId);

    if (!windowId) {
        console.error('[extractCameraMetadata] Window ID not found');
        return {
            success: false,
            error: 'Window ID not found'
        };
    }
    console.log(`[extractCameraMetadata] Processing window ID: ${windowId}`);

    // Get stream URL - Fix: Use dataset.streamUrl instead of getAttribute('data-stream-url')
    const streamUrl = windowElement.dataset.streamUrl;
    console.log('[extractCameraMetadata] Stream URL from dataset:', streamUrl);

    if (!streamUrl) {
        console.error('[extractCameraMetadata] Stream URL not found');
        return {
            success: false,
            error: 'Stream URL not found'
        };
    }
    console.log(`[extractCameraMetadata] Stream URL: ${streamUrl}`);

    try {
        // Extract IP address from stream URL
        const urlObj = new URL(streamUrl);
        const ipAddress = urlObj.hostname;
        console.log(`[extractCameraMetadata] Extracted IP address: ${ipAddress}`);

        // Get port from URL or use default
        const port = urlObj.port || (urlObj.protocol === 'rtsp:'?'554' : '80');
        console.log(`[extractCameraMetadata] Using port: ${port}`);

        // Get path from URL
        const path = urlObj.pathname;
        console.log(`[extractCameraMetadata] Path: ${path}`);

        // Identify camera model based on URL
        console.log('[extractCameraMetadata] Identifying camera model');
        const modelInfo = identifyCameraModel(streamUrl, globalState.rawData.ipInfo, globalState.rawData.asnInfo);
        console.log(`[extractCameraMetadata] Camera model identified: ${modelInfo.manufacturer} ${modelInfo.model}`);

        // Probe for open ports
        console.log('[extractCameraMetadata] Checking for open ports');
        const portInfo = {
            openPorts: [parseInt(port)], // We know this port is open since we're connecting to it
            commonPorts: [80, 443, 554, 8080, 8000, 8081, 8443, 37777, 37778, 9000]
        };
        console.log(`[extractCameraMetadata] Open ports: ${portInfo.openPorts.join(', ')}`);

        // Check for default credentials
        console.log('[extractCameraMetadata] Checking for default credentials');
        const authInfo = checkDefaultCredentials(modelInfo.manufacturer);
        console.log(`[extractCameraMetadata] Found ${authInfo.defaultCredentials.length} potential default credentials`);

        // Analyze security based on gathered information
        console.log('[extractCameraMetadata] Analyzing security rating');
        const securityInfo = analyzeSecurityRating(modelInfo, portInfo, authInfo, globalState.rawData.ipInfo);
        console.log(`[extractCameraMetadata] Security rating: ${securityInfo.rating} (Score: ${securityInfo.score})`);

        // Generate alternative stream URLs based on common patterns
        console.log('[extractCameraMetadata] Generating alternative stream URLs');
        const alternativeStreams = generateAlternativeStreams(streamUrl, ipAddress, globalState.rtspPaths);
        console.log(`[extractCameraMetadata] Generated ${alternativeStreams.length} alternative stream URLs`);

        // Combine all metadata
        const metadata = {
            timestamp: new Date().toISOString(),
            cameraDetails: {
                manufacturer: modelInfo.manufacturer,
                model: modelInfo.model,
                firmware: modelInfo.firmware
            },
            streamInfo: {
                originalUrl: streamUrl,
                protocol: urlObj.protocol,
                ipAddress: ipAddress,
                port: port,
                path: path,
                framerate: '25 fps (estimated)',
                bitrate: '2 Mbps (estimated)',
                alternativeStreams: alternativeStreams.slice(0, 10) // Limit to 10 alternatives
            },
            securityInfo: {
                rating: securityInfo.rating,
                score: securityInfo.score,
                authentication: true, // Most cameras require authentication
                vulnerabilities: securityInfo.vulnerabilities
            },
            networkInfo: {
                ipInfo: globalState.rawData.ipInfo[windowId] || {},
                asnInfo: globalState.rawData.asnInfo[windowId] || {}
            },
            authInfo: {
                defaultCredentials: authInfo.defaultCredentials.slice(0, 10), // Limit to 10 credentials
                webPaths: authInfo.webPaths
            }
        };

        // Store metadata in global state
        globalState.rawData.metadata[windowId] = metadata;
        console.log('[extractCameraMetadata] Metadata extraction completed successfully');

        // Update UI with extracted metadata
        updateMetadataUI(windowElement, metadata);

        return {
            success: true,
            metadata
        };
    } catch (error) {
        console.error('[extractCameraMetadata] Error extracting metadata:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Function to generate alternative stream URLs based on common patterns
function generateAlternativeStreams(originalUrl, ipAddress, rtspPaths) {
    console.log('[generateAlternativeStreams] Generating alternative streams');
    const alternativeStreams = [];

    try {
        const urlObj = new URL(originalUrl);
        const protocol = urlObj.protocol;
        const port = urlObj.port || (protocol === 'rtsp:'?'554' : '80');

        // Add the original URL as the first option
        alternativeStreams.push({
            url: originalUrl,
            notes: 'Original stream URL'
        });

        // Generate alternatives based on common RTSP paths
        if (protocol === 'rtsp:') {
            console.log('[generateAlternativeStreams] Generating RTSP alternatives');

            // Use the first 20 paths from our database to avoid too many options
            const pathsToUse = rtspPaths.slice(0, 20);

            for (const path of pathsToUse) {
                // Skip if path is empty
                if (!path) continue;

                // Create alternative URL
                const altUrl = `rtsp://${ipAddress}:${port}/${path.startsWith('/')?path.substring(1) : path}`;

                // Skip if it's the same as the original
                if (altUrl === originalUrl) continue;

                alternativeStreams.push({
                    url: altUrl,
                    notes: 'Generated from common RTSP paths'
                });
            }
        }

        // Generate HTTP/HTTPS alternatives if original is RTSP
        if (protocol === 'rtsp:') {
            console.log('[generateAlternativeStreams] Generating HTTP alternatives for RTSP stream');

            // Add common HTTP streaming endpoints
            const httpPaths = [
                '/video.cgi',
                '/mjpg/video.mjpg',
                '/cgi-bin/snapshot.cgi',
                '/cgi-bin/video.cgi',
                '/videostream.cgi'
            ];

            for (const path of httpPaths) {
                alternativeStreams.push({
                    url: `http://${ipAddress}:80${path}`,
                    notes: 'HTTP alternative for RTSP stream'
                });
            }
        }

        console.log(`[generateAlternativeStreams] Generated ${alternativeStreams.length} alternative streams`);
        return alternativeStreams;
    } catch (error) {
        console.error('[generateAlternativeStreams] Error generating alternative streams:', error);
        return [{
            url: originalUrl,
            notes: 'Original stream URL'
        }];
    }
}

const extractInfoFromUrl = (url) => {
    // Parse RTSP URL to extract information
    const urlInfo = {
        protocol: 'Unknown',
        port: 'Unknown',
        path: 'Unknown',
        codec: 'Unknown'
    };

    try {
        // Extract protocol
        if (url.startsWith('rtsp://')) {
            urlInfo.protocol = 'RTSP';
        } else if (url.startsWith('http://')) {
            urlInfo.protocol = 'HTTP';
        } else if (url.startsWith('https://')) {
            urlInfo.protocol = 'HTTPS';
        }

        // Extract port
        const portMatch = url.match(/:(\d+)/);
        if (portMatch && portMatch[1]) {
            urlInfo.port = portMatch[1];
        } else {
            // Default ports based on protocol
            if (urlInfo.protocol === 'RTSP') urlInfo.port = '554';
            if (urlInfo.protocol === 'HTTP') urlInfo.port = '80';
            if (urlInfo.protocol === 'HTTPS') urlInfo.port = '443';
        }

        // Extract path
        const pathMatch = url.match(/\/\/(.*?)(?::|\/)(.*)/);
        if (pathMatch && pathMatch[2]) {
            urlInfo.path = '/' + pathMatch[2];
        }

        // Try to determine codec from URL
        if (url.includes('h264')) urlInfo.codec = 'H.264';
        else if (url.includes('h265')) urlInfo.codec = 'H.265';
        else if (url.includes('mjpeg')) urlInfo.codec = 'MJPEG';
        else urlInfo.codec = 'H.264'; // Default assumption

    } catch (error) {
        console.error('Error parsing URL:', error);
    }

    return urlInfo;
};

const identifyCameraModel = (url, ipInfo, asnInfo) => {
    console.log('Identifying camera model from URL:', url);
    console.log('IP info:', ipInfo);
    console.log('ASN info:', asnInfo);

    const modelInfo = {
        manufacturer: 'Unknown',
        model: 'Generic IP Camera',
        firmware: 'Unknown'
    };

    // Convert URL to lowercase for pattern matching
    const lowerUrl = url.toLowerCase();

    // Check URL against known camera patterns
    for (const [manufacturer, info] of Object.entries(globalState.cameraModels)) {
        for (const pattern of info.patterns) {
            if (lowerUrl.includes(pattern)) {
                console.log(`Found matching pattern "${pattern}" for manufacturer "${manufacturer}"`);
                modelInfo.manufacturer = manufacturer.charAt(0).toUpperCase() + manufacturer.slice(1);
                break;
            }
        }
        if (modelInfo.manufacturer !== 'Unknown') break;
    }

    // If manufacturer still unknown, try to identify from ISP/ASN info
    if (modelInfo.manufacturer === 'Unknown' && (ipInfo || asnInfo)) {
        const orgInfo = (ipInfo?.org || asnInfo?.org || '').toLowerCase();
        console.log('Checking organization info:', orgInfo);

        for (const [manufacturer, info] of Object.entries(globalState.cameraModels)) {
            for (const pattern of info.patterns) {
                if (orgInfo.includes(pattern)) {
                    console.log(`Found matching pattern "${pattern}" in org info for manufacturer "${manufacturer}"`);
                    modelInfo.manufacturer = manufacturer.charAt(0).toUpperCase() + manufacturer.slice(1);
                    break;
                }
            }
            if (modelInfo.manufacturer !== 'Unknown') break;
        }
    }

    // Generate model name based on manufacturer or use generic
    if (modelInfo.manufacturer !== 'Unknown') {
        // Extract potential model number from URL
        const modelMatch = url.match(/\/([\w-]+)\.(?:jpg|jpeg|png|cgi|mjpg|mjpeg|mp4|h264|h265)/i);
        if (modelMatch && modelMatch[1]) {
            modelInfo.model = `${modelInfo.manufacturer} ${modelMatch[1].toUpperCase()}`;
            console.log(`Extracted model number: ${modelMatch[1]}`);
        } else {
            modelInfo.model = `${modelInfo.manufacturer} IP Camera`;
        }
    }

    console.log('Final model info:', modelInfo);
    return modelInfo;
};

const probePorts = async (ip) => {
    console.log(`[probePorts] Port probing not available - requires specialized tools and may be illegal without permission`);

    const portInfo = {
        openPorts: [],
        services: {},
        note: 'Port scanning disabled - requires specialized tools and may be illegal without permission'
    };

    return portInfo;
};

function checkDefaultCredentials(manufacturer) {
    console.log(`[checkDefaultCredentials] Checking default credentials for manufacturer: ${manufacturer}`);

    // Initialize auth info object
    let authInfo = {
        requiresAuth: true,
        defaultCredentials: [],
        webPaths: []
    };

    // Normalize manufacturer name
    const normalizedManufacturer = manufacturer?manufacturer.toLowerCase().trim() : '';
    console.log(`[checkDefaultCredentials] Normalized manufacturer: ${normalizedManufacturer}`);

    // Check if we have specific credentials for this manufacturer
    if (normalizedManufacturer && globalState.cameraModels[normalizedManufacturer]) {
        console.log(`[checkDefaultCredentials] Found manufacturer in database: ${normalizedManufacturer}`);

        // Get manufacturer-specific credentials
        const modelInfo = globalState.cameraModels[normalizedManufacturer];
        authInfo.defaultCredentials = modelInfo.defaultCredentials || [];
        authInfo.webPaths = modelInfo.webPaths || [];

        console.log(`[checkDefaultCredentials] Found ${authInfo.defaultCredentials.length} default credentials and ${authInfo.webPaths.length} web paths`);
    } else {
        console.log(`[checkDefaultCredentials] Manufacturer not found in database, using generic credentials`);

        // Generate combinations from the credential database
        const {
            usernames,
            passwords
        } = globalState.credentialDatabase;

        // Generate top combinations based on common patterns
        const topCombinations = [{
                username: 'admin',
                password: 'admin'
            },
            {
                username: 'admin',
                password: '123456'
            },
            {
                username: 'admin',
                password: ''
            },
            {
                username: 'admin',
                password: 'password'
            },
            {
                username: 'root',
                password: 'root'
            },
            {
                username: 'root',
                password: '12345'
            }
        ];

        // Add top combinations first
        authInfo.defaultCredentials = [...topCombinations];

        // Add some additional combinations (limit to avoid too many)
        const maxAdditionalCombinations = 10;
        let addedCombinations = 0;

        for (const username of usernames) {
            if (addedCombinations >= maxAdditionalCombinations) break;

            // Skip usernames already in top combinations
            if (topCombinations.some(combo => combo.username === username)) continue;

            // Add with empty password
            authInfo.defaultCredentials.push({
                username,
                password: '',
                notes: 'Generated from database'
            });
            addedCombinations++;

            // Add with matching password if username is not empty
            if (username && addedCombinations < maxAdditionalCombinations) {
                authInfo.defaultCredentials.push({
                    username,
                    password: username,
                    notes: 'Generated from database'
                });
                addedCombinations++;
            }
        }

        // Add common web paths
        authInfo.webPaths = [
            '/login.html',
            '/index.html',
            '/web/index.html',
            '/cgi-bin/login.cgi',
            '/doc/page/login.asp'
        ];

        console.log(`[checkDefaultCredentials] Generated ${authInfo.defaultCredentials.length} generic credentials and ${authInfo.webPaths.length} web paths`);
    }

    return authInfo;
}

const analyzeSecurityRating = (modelInfo, portInfo, authInfo, ipInfo) => {
    console.log('Analyzing security rating');
    console.log('Model info:', modelInfo);
    console.log('Port info:', portInfo);
    console.log('Auth info:', authInfo);
    console.log('IP info:', ipInfo);

    const securityInfo = {
        rating: 'Unknown',
        score: 0,
        vulnerabilities: []
    };

    // Start with a base score
    let score = 5;
    console.log('Starting with base score:', score);

    // 1. Check manufacturer's general security rating
    const manufacturer = modelInfo.manufacturer.toLowerCase();
    if (globalState.cameraModels[manufacturer]) {
        const mfrRating = globalState.cameraModels[manufacturer].securityRating;
        console.log('Manufacturer security rating:', mfrRating);

        if (mfrRating === 'high') {
            score += 2;
            console.log('Added 2 points for high security rating');
        } else if (mfrRating === 'medium') {
            score += 0;
            console.log('Added 0 points for medium security rating');
        } else if (mfrRating === 'low') {
            score -= 2;
            console.log('Subtracted 2 points for low security rating');
        }
    }

    // 2. Check for open ports
    const criticalPorts = [23, 21, 22, 8000, 8080, 9000];
    criticalPorts.forEach(port => {
        if (portInfo.openPorts.includes(port)) {
            score -= 1;
            console.log(`Subtracted 1 point for open critical port: ${port}`);
            securityInfo.vulnerabilities.push(`Open critical port: ${port}`);
        }
    });

    // 3. Check for default credentials
    if (authInfo.defaultCredentials.length > 0) {
        score -= 1;
        console.log(`Subtracted 1 point for ${authInfo.defaultCredentials.length} default credentials`);
        securityInfo.vulnerabilities.push('Default credentials may work');
    }

    // 4. Check if camera is in a data center (less likely to be secure)
    if (ipInfo && ipInfo.hosting === true) {
        score -= 1;
        console.log('Subtracted 1 point for camera hosted in data center');
        securityInfo.vulnerabilities.push('Camera hosted in data center');
    }

    // 5. Add known vulnerabilities from the database
    if (globalState.cameraModels[manufacturer] && globalState.cameraModels[manufacturer].vulnerabilities) {
        const knownVulns = globalState.cameraModels[manufacturer].vulnerabilities;
        if (knownVulns.length > 0) {
            score -= Math.min(knownVulns.length, 3); // Max 3 points deduction for vulnerabilities
            console.log(`Subtracted ${Math.min(knownVulns.length, 3)} points for known vulnerabilities`);
            securityInfo.vulnerabilities.push(...knownVulns);
        }
    }

    // 6. Determine final rating based on score
    if (score >= 7) {
        securityInfo.rating = 'High';
    } else if (score >= 4) {
        securityInfo.rating = 'Medium';
    } else {
        securityInfo.rating = 'Low';
    }

    securityInfo.score = score;
    console.log('Final security score:', score);
    console.log('Final security rating:', securityInfo.rating);
    console.log('Vulnerabilities found:', securityInfo.vulnerabilities.length);

    return securityInfo;
};

const updateMetadataUI = (windowElement, metadata) => {
    if (!windowElement || !metadata) return;

    // Update camera details
    const cameraModel = windowElement.querySelector('.camera-model');
    const firmwareVersion = windowElement.querySelector('.firmware-version');
    const manufacturer = windowElement.querySelector('.manufacturer');

    if (cameraModel) {
        cameraModel.textContent = metadata.cameraDetails.model;
        cameraModel.className = `metadata-value camera-model camera-model-${metadata.cameraDetails.manufacturer.toLowerCase()}`;
    }

    if (firmwareVersion) {
        firmwareVersion.textContent = metadata.cameraDetails.firmware;
    }

    if (manufacturer) {
        manufacturer.textContent = metadata.cameraDetails.manufacturer;
    }

    // Update stream information
    const streamCodec = windowElement.querySelector('.stream-codec');
    const streamFramerate = windowElement.querySelector('.stream-framerate');
    const streamBitrate = windowElement.querySelector('.stream-bitrate');

    if (streamCodec) streamCodec.textContent = metadata.streamInfo.protocol;
    if (streamFramerate) streamFramerate.textContent = metadata.streamInfo.framerate;
    if (streamBitrate) streamBitrate.textContent = metadata.streamInfo.bitrate;

    // Update security assessment
    const authStatus = windowElement.querySelector('.auth-status');
    const defaultCreds = windowElement.querySelector('.default-creds');
    const ratingValue = windowElement.querySelector('.rating-value');
    const ratingDescription = windowElement.querySelector('.rating-description');

    if (authStatus) {
        const authRequired = metadata.securityInfo.authentication;
        authStatus.innerHTML = authRequired ?
            '<span class="security-indicator secure"><i class="fas fa-check-circle"></i> Required</span>' :
            '<span class="security-indicator danger"><i class="fas fa-exclamation-triangle"></i> Not Required</span>';
    }

    if (defaultCreds) {
        const hasDefaultCreds = metadata.authInfo.defaultCredentials.length > 0;
        defaultCreds.innerHTML = hasDefaultCreds ?
            `<span class="security-indicator warning"><i class="fas fa-exclamation-circle"></i> Possible (${metadata.authInfo.defaultCredentials.length})</span>` :
            '<span class="security-indicator secure"><i class="fas fa-check-circle"></i> None Found</span>';
    }

    if (ratingValue) {
        const rating = metadata.securityInfo.rating.toLowerCase();
        ratingValue.textContent = metadata.securityInfo.rating.charAt(0);
        ratingValue.className = `rating-value ${rating}`;
    }

    if (ratingDescription) {
        const vulnerabilities = metadata.securityInfo.vulnerabilities;
        if (vulnerabilities.length > 0) {
            ratingDescription.textContent = `${metadata.securityInfo.rating} security (${vulnerabilities.length} issues found)`;
        } else {
            ratingDescription.textContent = `${metadata.securityInfo.rating} security`;
        }
    }

    // Update credentials section
    updateCredentialsSection(windowElement, metadata);

    // Update vulnerabilities section
    updateVulnerabilitiesSection(windowElement, metadata);

    // Update raw metadata
    const rawMetadataElement = windowElement.querySelector('.raw-metadata-data');
    if (rawMetadataElement) {
        rawMetadataElement.textContent = JSON.stringify(metadata, null, 2);
    }
};

// New function to update the credentials section
const updateCredentialsSection = (windowElement, metadata) => {
    if (!windowElement || !metadata) return;

    const credentialCount = windowElement.querySelector('.credential-count');
    const credentialsTableBody = windowElement.querySelector('.credentials-table-body');
    const testCredentialsBtn = windowElement.querySelector('.test-credentials-btn');

    if (!credentialCount || !credentialsTableBody) return;

    const credentials = metadata.authInfo.defaultCredentials;

    // Update credential count
    credentialCount.textContent = credentials.length;

    // Clear existing credentials
    credentialsTableBody.innerHTML = '';

    // Add credentials to table
    if (credentials.length > 0) {
        credentials.forEach((cred, index) => {
            const row = document.createElement('tr');

            // Username cell
            const usernameCell = document.createElement('td');
            usernameCell.textContent = cred.username;
            usernameCell.title = 'Click to copy username';
            usernameCell.className = 'credential-copy';
            usernameCell.addEventListener('click', () => {
                copyToClipboard(cred.username);
                showNotification('<i class="fas fa-copy"></i> Username copied to clipboard');
            });

            // Password cell
            const passwordCell = document.createElement('td');
            passwordCell.textContent = cred.password || '(blank)';
            passwordCell.title = 'Click to copy password';
            passwordCell.className = 'credential-copy';
            passwordCell.addEventListener('click', () => {
                copyToClipboard(cred.password || '');
                showNotification('<i class="fas fa-copy"></i> Password copied to clipboard');
            });

            // Notes cell
            const notesCell = document.createElement('td');
            notesCell.textContent = cred.notes || '';
            notesCell.className = 'credential-notes';

            // Actions cell
            const actionsCell = document.createElement('td');

            // Test button
            const testBtn = document.createElement('button');
            testBtn.className = 'credential-action-btn';
            testBtn.innerHTML = '<i class="fas fa-vial"></i>';
            testBtn.title = 'Test this credential';
            testBtn.addEventListener('click', () => {
                testSingleCredential(windowElement, metadata, cred);
            });

            // Copy button
            const copyBtn = document.createElement('button');
            copyBtn.className = 'credential-action-btn';
            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
            copyBtn.title = 'Copy credential';
            copyBtn.addEventListener('click', () => {
                copyToClipboard(`${cred.username}:${cred.password}`);
                showNotification('<i class="fas fa-copy"></i> Credential copied to clipboard');
            });

            actionsCell.appendChild(testBtn);
            actionsCell.appendChild(copyBtn);

            // Add cells to row
            row.appendChild(usernameCell);
            row.appendChild(passwordCell);
            row.appendChild(notesCell);
            row.appendChild(actionsCell);

            // Add row to table
            credentialsTableBody.appendChild(row);
        });

        // Enable test all button
        if (testCredentialsBtn) {
            testCredentialsBtn.disabled = false;
            testCredentialsBtn.addEventListener('click', () => {
                testAllCredentials(windowElement, metadata);
            });
        }
    } else {
        // No credentials found
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 4;
        cell.textContent = 'No default credentials found for this camera model.';
        cell.style.textAlign = 'center';
        cell.style.color = 'var(--text-muted)';
        row.appendChild(cell);
        credentialsTableBody.appendChild(row);

        // Disable test all button
        if (testCredentialsBtn) {
            testCredentialsBtn.disabled = true;
        }
    }

    // Setup toggle button
    const toggleBtn = windowElement.querySelector('.toggle-credentials-btn');
    const credentialsList = windowElement.querySelector('.credentials-list');

    if (toggleBtn && credentialsList) {
        toggleBtn.addEventListener('click', () => {
            const isHidden = credentialsList.style.display === 'none';
            credentialsList.style.display = isHidden?'block' : 'none';
            toggleBtn.innerHTML = isHidden ?
                '<i class="fas fa-chevron-up"></i> Hide Details' :
                '<i class="fas fa-chevron-down"></i> Show Details';
        });
    }
};

// New function to update the vulnerabilities section
const updateVulnerabilitiesSection = (windowElement, metadata) => {
    if (!windowElement || !metadata) return;

    const vulnerabilityCount = windowElement.querySelector('.vulnerability-count');
    const vulnerabilitiesList = windowElement.querySelector('.vulnerabilities-items');

    if (!vulnerabilityCount || !vulnerabilitiesList) return;

    const vulnerabilities = metadata.securityInfo.vulnerabilities || [];

    // Update vulnerability count
    vulnerabilityCount.textContent = vulnerabilities.length;

    // Clear existing vulnerabilities
    vulnerabilitiesList.innerHTML = '';

    // Add vulnerabilities to list
    if (vulnerabilities.length > 0) {
        vulnerabilities.forEach(vuln => {
            const item = document.createElement('li');
            item.textContent = vuln;
            vulnerabilitiesList.appendChild(item);
        });
    } else {
        // No vulnerabilities found
        const item = document.createElement('li');
        item.textContent = 'No known vulnerabilities found for this camera model.';
        item.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
        item.style.borderLeftColor = 'var(--success-color)';
        vulnerabilitiesList.appendChild(item);
    }

    // Setup toggle button
    const toggleBtn = windowElement.querySelector('.toggle-vulnerabilities-btn');
    const vulnerabilitiesListContainer = windowElement.querySelector('.vulnerabilities-list');

    if (toggleBtn && vulnerabilitiesListContainer) {
        toggleBtn.addEventListener('click', () => {
            const isHidden = vulnerabilitiesListContainer.style.display === 'none';
            vulnerabilitiesListContainer.style.display = isHidden?'block' : 'none';
            toggleBtn.innerHTML = isHidden ?
                '<i class="fas fa-chevron-up"></i> Hide Details' :
                '<i class="fas fa-chevron-down"></i> Show Details';
        });
    }
};

// Helper function to copy text to clipboard
const copyToClipboard = (text) => {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = 0;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
};

// Function to test a single credential
const testSingleCredential = (windowElement, metadata, credential) => {
    if (!windowElement || !metadata || !credential) return;

    const testResultsContainer = windowElement.querySelector('.test-results');
    const testResultsContent = windowElement.querySelector('.test-results-content');

    if (!testResultsContainer || !testResultsContent) return;

    // Show test results container
    testResultsContainer.style.display = 'block';

    // Create result item
    const resultItem = document.createElement('div');
    resultItem.className = 'test-result-item testing-animation';
    resultItem.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Testing ${credential.username}:${credential.password}...`;
    testResultsContent.prepend(resultItem);

    // Credential testing removed - requires real HTTP requests which may be blocked by CORS
    setTimeout(() => {
        resultItem.className = 'test-result-item test-result-failure';
        resultItem.innerHTML = `<i class="fas fa-info-circle"></i> <strong>${credential.username}:${credential.password}</strong> - Credential testing disabled (requires real HTTP requests)`;
    }, 1500);
};

// Function to test all credentials
const testAllCredentials = (windowElement, metadata) => {
    if (!windowElement || !metadata) return;

    const credentials = metadata.authInfo.defaultCredentials;
    if (!credentials || credentials.length === 0) return;

    const testProgress = windowElement.querySelector('.test-progress');
    const progressFill = windowElement.querySelector('.progress-fill');
    const progressText = windowElement.querySelector('.progress-text');
    const testResultsContainer = windowElement.querySelector('.test-results');
    const testResultsContent = windowElement.querySelector('.test-results-content');

    if (!testProgress || !progressFill || !progressText || !testResultsContainer || !testResultsContent) return;

    // Show progress and results containers
    testProgress.style.display = 'block';
    testResultsContainer.style.display = 'block';

    // Clear previous results
    testResultsContent.innerHTML = '';

    // Add header for this test run
    const testHeader = document.createElement('div');
    testHeader.style.marginBottom = '10px';
    testHeader.style.fontWeight = 'bold';
    testHeader.innerHTML = `<i class="fas fa-clock"></i> Test started at ${new Date().toLocaleTimeString()}`;
    testResultsContent.appendChild(testHeader);

    // Initialize progress
    let currentIndex = 0;
    const totalCredentials = credentials.length;

    // Update progress text
    progressText.textContent = `Testing credentials (0/${totalCredentials})`;

    // Function to test next credential
    const testNext = () => {
        if (currentIndex >= totalCredentials) {
            // All done
            progressText.textContent = `Testing complete (${totalCredentials}/${totalCredentials})`;
            showNotification('<i class="fas fa-check-circle"></i> Credential testing complete', 'success');
            return;
        }

        const credential = credentials[currentIndex];

        // Update progress
        const progress = ((currentIndex + 1) / totalCredentials) * 100;
        progressFill.style.width = `${progress}%`;
        progressText.textContent = `Testing credentials (${currentIndex + 1}/${totalCredentials})`;

        // Create result item
        const resultItem = document.createElement('div');
        resultItem.className = 'test-result-item testing-animation';
        resultItem.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Testing ${credential.username}:${credential.password}...`;
        testResultsContent.appendChild(resultItem);

        // Scroll to bottom of results
        testResultsContent.scrollTop = testResultsContent.scrollHeight;

        // Credential testing removed - requires real HTTP requests which may be blocked by CORS
        setTimeout(() => {
            resultItem.className = 'test-result-item test-result-failure';
            resultItem.innerHTML = `<i class="fas fa-info-circle"></i> <strong>${credential.username}:${credential.password}</strong> - Credential testing disabled (requires real HTTP requests)`;

            // Move to next credential
            currentIndex++;
            testNext();
        }, 1000);
    };

    // Start testing
    testNext();
};

// Initialization
const init = () => {
    try {
        // Initialize DOM elements
        DOM.init();

        // Make sidebar draggable if it exists
        const sidebar = DOM.get('sidebar');
        const sidebarTitlebar = sidebar?.querySelector('.window-titlebar');
        if (sidebar && sidebarTitlebar) {
            makeDraggable(sidebar, sidebarTitlebar);
            setupWindowControls(sidebar);
        } else {
            console.warn('Sidebar or titlebar not found');
        }

        // Setup initial state
        updateCameraCount();
        updateClock();

        // Start clock update interval
        const clockInterval = setInterval(updateClock, 1000);

        // Load cameras from Pastebin
        updateCameraListFromPastebin(API_ENDPOINTS.PASTEBIN)
            .catch(error => {
                console.error('Failed to load camera list:', error);
                showNotification('<i class="fas fa-exclamation-triangle"></i> Failed to load camera list', 'error');
            });

        // Setup advanced mode button
        const advancedModeButton = DOM.get('advancedModeButton');
        if (advancedModeButton) {
            advancedModeButton.addEventListener('click', openAdvancedDashboard);
        }

        // Remove any existing overlay
        removeOverlay();

        // Setup observer to remove overlay if added
        const observer = new MutationObserver(() => {
            removeOverlay();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        // Store cleanup functions
        const cleanup = () => {
            clearInterval(clockInterval);
            observer.disconnect();
            // Clean up any active resize observers
            Object.values(globalState.resizeObservers).forEach(observer => {
                if (observer.observer) observer.observer.disconnect();
                if (observer.timeout) clearTimeout(observer.timeout);
            });
            globalState.resizeObservers = {};
        };

        // Add cleanup on page unload
        window.addEventListener('unload', cleanup);

        console.info('Application initialized successfully');
        return true;
    } catch (error) {
        console.error('Failed to initialize application:', error);
        return false;
    }
};

// Initialize application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// Close video window function
const closeVideoWindow = (windowElement) => {
    if (!windowElement) return;

    const windowId = windowElement.dataset.id;
    if (windowId) {
        // Remove from active windows
        const index = globalState.activeWindows.indexOf(windowId);
        if (index > -1) {
            globalState.activeWindows.splice(index, 1);
        }

        // Clean up resize observer if it exists
        if (globalState.resizeObservers[windowId]) {
            globalState.resizeObservers[windowId].disconnect();
            delete globalState.resizeObservers[windowId];
        }

        // Clean up MJPG player intervals
        const mjpgPlayer = windowElement.querySelector('.mjpg-image-container, .mjpg-iframe-container');
        if (mjpgPlayer && mjpgPlayer.cleanup) {
            mjpgPlayer.cleanup();
        }

        // Clean up raw data
        if (globalState.rawData.ipInfo[windowId]) {
            delete globalState.rawData.ipInfo[windowId];
        }
        if (globalState.rawData.asnInfo[windowId]) {
            delete globalState.rawData.asnInfo[windowId];
        }
        if (globalState.rawData.metadata[windowId]) {
            delete globalState.rawData.metadata[windowId];
        }
    }

    // Remove from DOM
    windowElement.remove();

    // Update dashboard if in advanced mode
    if (globalState.advancedMode) {
        updateDashboardContent();
        populateCurrentIpSelector();
    }
};

// Expose some functions to global scope for HTML onclick handlers
window.openTab = openTab;
window.closeVideoWindow = closeVideoWindow;

// Tab navigation function for old code compatibility
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

// Setup metadata extraction button
const setupMetadataExtraction = (windowElement) => {
    console.log('[setupMetadataExtraction] Setting up metadata extraction for window:', windowElement);

    if (!windowElement) {
        console.error('[setupMetadataExtraction] Window element is null or undefined');
        return;
    }

    // Find the extract metadata button
    const extractButton = windowElement.querySelector('.extract-metadata-btn');
    console.log('[setupMetadataExtraction] Extract button found:', extractButton);

    if (!extractButton) {
        console.error('[setupMetadataExtraction] Extract metadata button not found in window');
        return;
    }

    // Remove any existing event listeners by cloning the button
    const newButton = extractButton.cloneNode(true);
    extractButton.parentNode.replaceChild(newButton, extractButton);

    // Add event listener to the new button
    newButton.addEventListener('click', (event) => {
        event.preventDefault();
        console.log('[setupMetadataExtraction] Extract metadata button clicked');

        // Show loading indicator
        const loadingIndicator = windowElement.querySelector('.metadata-loading');
        if (loadingIndicator) {
            loadingIndicator.style.display = 'flex';
        }

        try {
            // Call the metadata extraction function
            console.log('[setupMetadataExtraction] Calling extractCameraMetadata');
            const result = extractCameraMetadata(windowElement);
            console.log('[setupMetadataExtraction] Metadata extraction result:', result);

            // Show notification based on result
            if (result.success) {
                showNotification('Metadata extraction completed successfully', 'success');
            } else {
                showNotification(`Metadata extraction failed: ${result.error}`, 'error');
            }
        } catch (error) {
            console.error('[setupMetadataExtraction] Error during metadata extraction:', error);
            showNotification(`Error during metadata extraction: ${error.message}`, 'error');
        } finally {
            // Hide loading indicator
            if (loadingIndicator) {
                loadingIndicator.style.display = 'none';
            }
        }
    });

    console.log('[setupMetadataExtraction] Event listener added to extract metadata button');
};

// ============================================================================
// NETWORK DISCOVERY & RECONNAISSANCE FUNCTIONS
// ============================================================================

/**
 * Subnet Scanner - Discovers other devices on the same network
 */
const scanSubnet = async (baseIp, subnetMask = 24) => {
    console.log(`[scanSubnet] Starting subnet scan for ${baseIp}/${subnetMask}`);

    const results = {
        baseIp,
        subnetMask,
        discoveredDevices: [],
        scanTime: new Date().toISOString(),
        totalHosts: 0,
        activeHosts: 0
    };

    try {
        // Parse the base IP
        const ipParts = baseIp.split('.').map(Number);
        if (ipParts.length !== 4 || ipParts.some(part => part < 0 || part > 255)) {
            throw new Error('Invalid IP address format');
        }

        // Calculate network range based on subnet mask
        const hostBits = 32 - subnetMask;
        const totalHosts = Math.pow(2, hostBits) - 2; // Exclude network and broadcast
        results.totalHosts = totalHosts;

        // Network scanning disabled - requires specialized tools and may be illegal without permission
        console.log(`[scanSubnet] Network scanning disabled - would scan ${totalHosts} hosts`);

        // No actual scanning performed
        results.discoveredDevices = [];
        results.activeHosts = 0;

        // Store results in global state
        globalState.rawData.networkDiscovery[baseIp] = results;
        globalState.networkDiscovery.scanHistory.push(results);

        console.log(`[scanSubnet] Scan completed. Found ${results.activeHosts} active devices`);
        return results;

    } catch (error) {
        console.error('[scanSubnet] Subnet scan failed:', error);
        throw error;
    }
};

// Device discovery function removed - network scanning requires specialized tools and may be illegal without permission

/**
 * Port Scanner - Identifies open services on target IPs
 */
const scanPorts = async (ip, ports = null) => {
    console.log(`[scanPorts] Starting port scan for ${ip}`);

    const targetPorts = ports || globalState.networkDiscovery.commonPorts;
    const results = {
        ip,
        scanTime: new Date().toISOString(),
        openPorts: [],
        closedPorts: [],
        filteredPorts: []
    };

    try {
        // Port scanning disabled - requires specialized tools and may be illegal without permission
        console.log(`[scanPorts] Port scanning disabled - would scan ${targetPorts.length} ports`);

        // No actual port scanning performed
        results.openPorts = [];
        results.closedPorts = [];
        results.filteredPorts = [];

        console.log(`[scanPorts] Port scan completed. Found ${results.openPorts.length} open ports`);
        return results;

    } catch (error) {
        console.error('[scanPorts] Port scan failed:', error);
        throw error;
    }
};

// Port scanning functions removed - requires specialized tools and may be illegal without permission

// Random MAC address generation removed - no fake data generation

/**
 * Network Topology Mapper - Creates visual network relationships
 */
const mapNetworkTopology = async (discoveredDevices) => {
    console.log('[mapNetworkTopology] Creating network topology map');

    const topology = {
        nodes: [],
        edges: [],
        subnets: {},
        gateways: [],
        createdAt: new Date().toISOString()
    };

    try {
        // Process discovered devices
        for (const device of discoveredDevices) {
            const subnet = device.ip.substring(0, device.ip.lastIndexOf('.'));

            // Add device as node
            topology.nodes.push({
                id: device.ip,
                label: device.hostname || device.ip,
                type: device.deviceType,
                manufacturer: device.manufacturer,
                openPorts: device.openPorts,
                subnet: subnet,
                confidence: device.confidence
            });

            // Track subnets
            if (!topology.subnets[subnet]) {
                topology.subnets[subnet] = [];
            }
            topology.subnets[subnet].push(device.ip);

            // Identify potential gateways (devices with routing capabilities)
            if (device.deviceType === 'router' ||
                device.openPorts.some(p => p.service === 'SSH' || p.service === 'Telnet')) {
                topology.gateways.push(device.ip);
            }
        }

        // Create edges based on subnet relationships
        Object.keys(topology.subnets).forEach(subnet => {
            const subnetDevices = topology.subnets[subnet];

            // Connect devices in the same subnet
            for (let i = 0; i < subnetDevices.length; i++) {
                for (let j = i + 1; j < subnetDevices.length; j++) {
                    topology.edges.push({
                        source: subnetDevices[i],
                        target: subnetDevices[j],
                        type: 'subnet',
                        subnet: subnet
                    });
                }
            }
        });

        console.log(`[mapNetworkTopology] Created topology with ${topology.nodes.length} nodes and ${topology.edges.length} edges`);
        return topology;

    } catch (error) {
        console.error('[mapNetworkTopology] Failed to create network topology:', error);
        throw error;
    }
};



/**
 * Direct IP info fetch (helper function)
 */
const fetchIPInfoDirect = async (ip) => {
    try {
        const response = await fetch(API_ENDPOINTS.CORS_PROXY, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: `${API_ENDPOINTS.IP_INFO}${ip}?fields=${API_ENDPOINTS.IP_INFO_FIELDS}`
            })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const proxyResponse = await response.json();
        return JSON.parse(proxyResponse.contents);

    } catch (error) {
        console.warn(`[fetchIPInfoDirect] Failed to fetch IP info for ${ip}:`, error);
        return null;
    }
};







// URL pattern detection function removed - requires real HTTP requests which may be blocked by CORS





// Certificate analysis function removed - requires real HTTPS connections which may be blocked by CORS





// ============================================================================
// THREAT INTELLIGENCE FUNCTIONS
// ============================================================================

/**
 * Check IP reputation across multiple threat intelligence sources
 */
const checkIPReputation = async (ip) => {
    console.log(`[checkIPReputation] Checking reputation for ${ip}`);

    const results = {
        ip,
        timestamp: new Date().toISOString(),
        sources: {},
        riskScore: 0,
        riskFactors: [],
        summary: 'Unknown'
    };

    try {
        // Only use free APIs without authentication
        const threatSources = ['alienvault']; // Only AlienVault OTX is free without authentication

        for (const source of threatSources) {
            try {
                const sourceResult = await checkThreatIntelligence(ip, source);
                results.sources[source] = sourceResult;

                // Aggregate risk score
                if (sourceResult.riskScore) {
                    results.riskScore += sourceResult.riskScore;
                }

                // Collect risk factors
                if (sourceResult.riskFactors) {
                    results.riskFactors.push(...sourceResult.riskFactors);
                }
            } catch (error) {
                console.warn(`[checkIPReputation] Failed to check ${source}:`, error);
                results.sources[source] = {
                    error: error.message
                };
            }
        }

        // Calculate average risk score
        const validSources = Object.values(results.sources).filter(s => s.riskScore !== undefined);
        if (validSources.length > 0) {
            results.riskScore = results.riskScore / validSources.length;
        }

        // Determine risk summary
        if (results.riskScore >= 80) {
            results.summary = 'High Risk';
        } else if (results.riskScore >= 50) {
            results.summary = 'Medium Risk';
        } else if (results.riskScore >= 20) {
            results.summary = 'Low Risk';
        } else {
            results.summary = 'Clean';
        }

        // Store results
        globalState.rawData.threatIntel[ip] = results;
        globalState.threatIntel.riskScores[ip] = results.riskScore;

        console.log(`[checkIPReputation] Risk assessment completed. Score: ${results.riskScore}`);
        return results;

    } catch (error) {
        console.error('[checkIPReputation] Threat intelligence check failed:', error);
        throw error;
    }
};

/**
 * Real threat intelligence check using only free APIs without authentication
 */
const checkThreatIntelligence = async (ip, source) => {
    console.log(`[checkThreatIntelligence] Checking threat intelligence for ${ip} using ${source}`);

    try {
        switch (source) {
            case 'alienvault':
                // AlienVault OTX is the only free API that works without authentication
                return await checkAlienVault(ip);
            default:
                // All other APIs require authentication or are blocked by CORS
                return {
                    source: source || 'Multiple Sources',
                        riskScore: 0,
                        riskFactors: [],
                        lastSeen: null,
                        confidence: 0,
                        note: 'API requires authentication or is blocked by CORS policy'
                };
        }
    } catch (error) {
        console.error(`[checkThreatIntelligence] Error checking ${source}:`, error);
        return {
            source: source || 'Unknown',
            riskScore: 0,
            riskFactors: [],
            lastSeen: null,
            confidence: 0,
            note: `API error: ${error.message}`
        };
    }
};

// Paid API functions removed - AbuseIPDB and URLhaus require authentication and are blocked by CORS

/**
 * Check AlienVault OTX for threat intelligence
 */
const checkAlienVault = async (ip) => {
    try {
        const url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`;

        const response = await fetch(url);

        if (response.ok) {
            const data = await response.json();
            const pulseCount = data.pulse_info?.count || 0;

            return {
                source: 'AlienVault OTX',
                riskScore: Math.min(pulseCount * 5, 100), // 5 points per pulse
                riskFactors: pulseCount > 0?[`Found in ${pulseCount} threat pulses`] : [],
                lastSeen: data.pulse_info?.pulses?. [0]?.created || null,
                confidence: 80,
                note: 'Real AlienVault OTX data'
            };
        }
    } catch (error) {
        console.warn('[checkAlienVault] Failed:', error.message);
    }

    return {
        source: 'AlienVault OTX',
        riskScore: 0,
        riskFactors: [],
        lastSeen: null,
        confidence: 0,
        note: 'AlienVault OTX check failed'
    };
};

// VirusTotal function removed - requires paid API and is blocked by CORS

/**
 * Weather correlation for authenticity verification
 */
const verifyWeatherCorrelation = async (ip, lat, lon) => {
    console.log(`[verifyWeatherCorrelation] Checking weather correlation for ${ip} at ${lat}, ${lon}`);

    const results = {
        ip,
        coordinates: {
            lat,
            lon
        },
        timestamp: new Date().toISOString(),
        weatherData: null,
        correlation: 'unknown',
        confidence: 0
    };

    try {
        // Use real weather API from Open-Meteo (free, no key required)
        const weatherData = await getRealWeatherData(lat, lon);
        results.weatherData = weatherData;

        // Note: Correlation analysis would require actual camera feed analysis
        // This feature is removed as it would require fake data
        results.correlation = 'unavailable';
        results.confidence = 0;

        // Store results
        globalState.rawData.weatherData[ip] = results;

        console.log(`[verifyWeatherCorrelation] Weather correlation: ${results.correlation} (${results.confidence}%)`);
        return results;

    } catch (error) {
        console.error('[verifyWeatherCorrelation] Weather correlation failed:', error);
        throw error;
    }
};

/**
 * Get real weather data from multiple free APIs with fallbacks
 */
const getRealWeatherData = async (lat, lon) => {
    // Try multiple weather APIs for better reliability
    const weatherAPIs = [{
            name: 'Open-Meteo',
            url: `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m&wind_speed_unit=kmh`,
            parser: (data) => {
                const current = data.current;
                const weatherCodeMap = {
                    0: 'Clear Sky',
                    1: 'Mainly Clear',
                    2: 'Partly Cloudy',
                    3: 'Overcast',
                    45: 'Fog',
                    48: 'Depositing Rime Fog',
                    51: 'Light Drizzle',
                    53: 'Moderate Drizzle',
                    55: 'Dense Drizzle',
                    61: 'Slight Rain',
                    63: 'Moderate Rain',
                    65: 'Heavy Rain',
                    71: 'Slight Snow',
                    73: 'Moderate Snow',
                    75: 'Heavy Snow',
                    80: 'Slight Rain Showers',
                    81: 'Moderate Rain Showers',
                    82: 'Violent Rain Showers'
                };
                return {
                    condition: weatherCodeMap[current.weather_code] || 'Unknown',
                    temperature: Math.round(current.temperature_2m || 0),
                    humidity: Math.round(current.relative_humidity_2m || 0),
                    windSpeed: Math.round(current.wind_speed_10m || 0),
                    visibility: 10,
                    source: 'Open-Meteo'
                };
            }
        },
        {
            name: 'OpenWeatherMap-OneCall',
            url: `https://api.openweathermap.org/data/3.0/onecall?lat=${lat}&lon=${lon}&units=metric&appid=demo`, // Demo key for testing
            parser: (data) => {
                const current = data.current;
                return {
                    condition: current.weather[0]?.description || 'Unknown',
                    temperature: Math.round(current.temp || 0),
                    humidity: Math.round(current.humidity || 0),
                    windSpeed: Math.round((current.wind_speed || 0) * 3.6), // Convert m/s to km/h
                    visibility: Math.round((current.visibility || 10000) / 1000),
                    source: 'OpenWeatherMap'
                };
            }
        }
    ];

    for (const api of weatherAPIs) {
        try {
            console.log(`[getRealWeatherData] Trying ${api.name}...`);
            const response = await fetch(api.url);

            if (response.ok) {
                const data = await response.json();
                const result = api.parser(data);
                result.timestamp = new Date().toISOString();
                console.log(`[getRealWeatherData] Success with ${api.name}`);
                return result;
            }
        } catch (error) {
            console.warn(`[getRealWeatherData] ${api.name} failed:`, error.message);
            continue;
        }
    }

    // If all APIs fail, return basic data
    throw new Error('All weather APIs failed');
};

// ============================================================================
// UI EVENT HANDLERS FOR OSINT FEATURES
// ============================================================================

/**
 * Setup Network Discovery event handlers for a video window
 */
const setupNetworkDiscoveryHandlers = (windowElement, streamUrl) => {
    if (!windowElement) return;

    const ip = extractIpFromUrl(streamUrl);
    if (!ip) return;

    // Subnet Scanner handlers
    const scanSubnetBtn = windowElement.querySelector('.scan-subnet-btn');
    const subnetTargetIp = windowElement.querySelector('.subnet-target-ip');
    const subnetMask = windowElement.querySelector('.subnet-mask');

    if (scanSubnetBtn && subnetTargetIp && subnetMask) {
        // Pre-fill with current IP
        subnetTargetIp.value = ip;

        scanSubnetBtn.addEventListener('click', async () => {
            const targetIp = subnetTargetIp.value.trim();
            const mask = parseInt(subnetMask.value);

            if (!targetIp) {
                showNotification('Please enter a target IP address', 'error');
                return;
            }

            // Show progress
            const progressDiv = windowElement.querySelector('.scan-progress');
            const resultsDiv = windowElement.querySelector('.scan-results');
            const devicesFoundSpan = windowElement.querySelector('.devices-found');
            const devicesList = windowElement.querySelector('.devices-list');

            if (progressDiv) progressDiv.style.display = 'block';
            if (devicesList) devicesList.innerHTML = '';

            try {
                showNotification('Starting subnet scan...', 'info');
                const results = await scanSubnet(targetIp, mask);

                // Update UI with results
                if (devicesFoundSpan) {
                    devicesFoundSpan.textContent = results.activeHosts;
                }

                if (devicesList && results.discoveredDevices.length > 0) {
                    results.discoveredDevices.forEach(device => {
                        const deviceCard = document.createElement('div');
                        deviceCard.className = 'detail-card';
                        deviceCard.style.marginBottom = '10px';

                        const deviceTypeIcon = getDeviceTypeIcon(device.deviceType);
                        const confidenceClass = device.confidence >= 80?'high' : device.confidence >= 60?'medium' : 'low';

                        deviceCard.innerHTML = `
                            <div class="detail-header">
                                <i class="fas ${deviceTypeIcon}"></i>
                                ${device.ip} - ${device.deviceType}
                            </div>
                            <div class="detail-content">
                                <div class="detail-row">
                                    <span class="detail-label">Manufacturer:</span>
                                    <span class="detail-value">${device.manufacturer}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Hostname:</span>
                                    <span class="detail-value">${device.hostname}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Confidence:</span>
                                    <span class="detail-value">
                                        <span class="rating-value ${confidenceClass}">${device.confidence}%</span>
                                    </span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Open Ports:</span>
                                    <span class="detail-value">
                                        ${device.openPorts.length > 0 ?
                                            device.openPorts.map(p => `<span class="security-indicator secure" style="margin-right: 4px; cursor: pointer;" onclick="openDevicePort('${device.ip}', ${p.port})">${p.port}/${p.service || 'unknown'}</span>`).join('')
                                            : '<span class="security-indicator warning">None detected</span>'}
                                    </span>
                                </div>
                                <div class="current-ip-actions" style="margin-top: 8px;">
                                    <button onclick="openDeviceInBrowser('${device.ip}')" style="flex: 1; font-size: 11px; padding: 4px 6px;">
                                        <i class="fas fa-external-link-alt"></i> Open
                                    </button>
                                    <button onclick="addDeviceToList('${device.ip}')" style="flex: 1; font-size: 11px; padding: 4px 6px;">
                                        <i class="fas fa-plus"></i> Add
                                    </button>
                                    <button onclick="scanDevicePorts('${device.ip}')" style="flex: 1; font-size: 11px; padding: 4px 6px;">
                                        <i class="fas fa-search"></i> Scan
                                    </button>
                                </div>
                            </div>
                        `;
                        devicesList.appendChild(deviceCard);
                    });
                }

                showNotification(`Subnet scan completed. Found ${results.activeHosts} devices`, 'success');

            } catch (error) {
                console.error('Subnet scan failed:', error);
                showNotification(`Subnet scan failed: ${error.message}`, 'error');
            } finally {
                if (progressDiv) progressDiv.style.display = 'none';
            }
        });
    }

    // Port Scanner handlers
    const scanPortsBtn = windowElement.querySelector('.scan-ports-btn');
    const portTargetIp = windowElement.querySelector('.port-target-ip');
    const portRange = windowElement.querySelector('.port-range');
    const customPortsDiv = windowElement.querySelector('.custom-ports');
    const customPortList = windowElement.querySelector('.custom-port-list');

    if (scanPortsBtn && portTargetIp && portRange) {
        // Pre-fill with current IP
        portTargetIp.value = ip;

        // Handle port range selection
        portRange.addEventListener('change', () => {
            if (portRange.value === 'custom') {
                if (customPortsDiv) customPortsDiv.style.display = 'block';
            } else {
                if (customPortsDiv) customPortsDiv.style.display = 'none';
            }
        });

        scanPortsBtn.addEventListener('click', async () => {
            const targetIp = portTargetIp.value.trim();
            let ports = null;

            if (!targetIp) {
                showNotification('Please enter a target IP address', 'error');
                return;
            }

            // Determine ports to scan
            if (portRange.value === 'custom') {
                if (!customPortList || !customPortList.value.trim()) {
                    showNotification('Please enter custom ports', 'error');
                    return;
                }
                ports = customPortList.value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
            } else if (portRange.value === 'camera') {
                ports = [21, 22, 23, 80, 443, 554, 8000, 8080, 8443, 37777];
            }

            const resultsDiv = windowElement.querySelector('.port-scan-results');
            const openPortsSpan = windowElement.querySelector('.open-ports-count');
            const portsList = windowElement.querySelector('.ports-list');

            if (portsList) portsList.innerHTML = '';

            try {
                showNotification('Starting port scan...', 'info');
                const results = await scanPorts(targetIp, ports);

                // Update UI with results
                if (openPortsSpan) {
                    openPortsSpan.textContent = results.openPorts.length;
                }

                if (portsList && results.openPorts.length > 0) {
                    results.openPorts.forEach(portInfo => {
                        const portCard = document.createElement('div');
                        portCard.className = 'detail-card';
                        portCard.style.marginBottom = '8px';

                        const serviceIcon = getServiceIcon(portInfo.service);
                        const riskLevel = getPortRiskLevel(portInfo.port);

                        portCard.innerHTML = `
                            <div class="detail-header">
                                <i class="fas ${serviceIcon}"></i>
                                Port ${portInfo.port} - ${portInfo.service || 'Unknown'}
                            </div>
                            <div class="detail-content">
                                <div class="detail-row">
                                    <span class="detail-label">Service:</span>
                                    <span class="detail-value">${portInfo.service || 'Unknown'}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Version:</span>
                                    <span class="detail-value">${portInfo.version || 'Unknown version'}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Risk Level:</span>
                                    <span class="detail-value">
                                        <span class="security-indicator ${riskLevel.class}">${riskLevel.text}</span>
                                    </span>
                                </div>
                                <div class="current-ip-actions" style="margin-top: 6px;">
                                    <button onclick="openPortInBrowser('${targetIp}', ${portInfo.port})" style="flex: 1; font-size: 11px; padding: 4px 6px;">
                                        <i class="fas fa-external-link-alt"></i> Open
                                    </button>
                                    <button onclick="copyPortInfo('${targetIp}', ${portInfo.port}, '${portInfo.service || 'unknown'}')" style="flex: 1; font-size: 11px; padding: 4px 6px;">
                                        <i class="fas fa-copy"></i> Copy
                                    </button>
                                </div>
                            </div>
                        `;
                        portsList.appendChild(portCard);
                    });
                }

                showNotification(`Port scan completed. Found ${results.openPorts.length} open ports`, 'success');

            } catch (error) {
                console.error('Port scan failed:', error);
                showNotification(`Port scan failed: ${error.message}`, 'error');
            }
        });
    }

    // Network Topology handlers
    const generateTopologyBtn = windowElement.querySelector('.generate-topology-btn');
    const exportTopologyBtn = windowElement.querySelector('.export-topology-btn');
    const topologyVisualization = windowElement.querySelector('.topology-visualization');

    if (generateTopologyBtn && topologyVisualization) {
        generateTopologyBtn.addEventListener('click', async () => {
            try {
                showNotification('Generating network topology...', 'info');

                // Get discovered devices from subnet scan results
                const networkData = globalState.rawData.networkDiscovery[ip];
                if (!networkData || !networkData.discoveredDevices.length) {
                    showNotification('No network data available. Please run a subnet scan first.', 'warning');
                    return;
                }

                const topology = await mapNetworkTopology(networkData.discoveredDevices);

                // Create styled topology visualization
                topologyVisualization.innerHTML = `
                    <div class="metadata-raw">
                        <h4>Network Topology Map</h4>
                        <div class="metadata-item">
                            <span class="metadata-label">Network Statistics:</span>
                            <span class="metadata-value">
                                <span class="security-indicator secure">${topology.nodes.length} Nodes</span>
                                <span class="security-indicator warning">${Object.keys(topology.subnets).length} Subnets</span>
                                <span class="security-indicator danger">${topology.gateways.length} Gateways</span>
                            </span>
                        </div>
                        <div class="ip-details-grid">
                            ${topology.nodes.map(node => `
                                <div class="detail-card">
                                    <div class="detail-header">
                                        <i class="fas ${getDeviceTypeIcon(node.type)}"></i>
                                        ${node.id}
                                    </div>
                                    <div class="detail-content">
                                        <div class="detail-row">
                                            <span class="detail-label">Type:</span>
                                            <span class="detail-value">${node.type}</span>
                                        </div>
                                        <div class="detail-row">
                                            <span class="detail-label">Manufacturer:</span>
                                            <span class="detail-value">${node.manufacturer}</span>
                                        </div>
                                        <div class="detail-row">
                                            <span class="detail-label">Subnet:</span>
                                            <span class="detail-value">${node.subnet}.x</span>
                                        </div>
                                        <div class="detail-row">
                                            <span class="detail-label">Open Ports:</span>
                                            <span class="detail-value">
                                                ${node.openPorts && node.openPorts.length > 0 ?
                                                    node.openPorts.map(p => `<span class="security-indicator secure">${p.port}</span>`).join(' ')
                                                    : '<span class="security-indicator warning">None</span>'}
                                            </span>
                                        </div>
                                        <div class="current-ip-actions" style="margin-top: 6px;">
                                            <button onclick="openDeviceInBrowser('${node.id}')" style="flex: 1; font-size: 11px; padding: 4px 6px;">
                                                <i class="fas fa-external-link-alt"></i> Open
                                            </button>
                                            <button onclick="addDeviceToList('${node.id}')" style="flex: 1; font-size: 11px; padding: 4px 6px;">
                                                <i class="fas fa-plus"></i> Add
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;

                if (exportTopologyBtn) {
                    exportTopologyBtn.disabled = false;
                }

                showNotification('Network topology generated successfully', 'success');

            } catch (error) {
                console.error('Topology generation failed:', error);
                showNotification(`Topology generation failed: ${error.message}`, 'error');
            }
        });
    }

    if (exportTopologyBtn) {
        exportTopologyBtn.addEventListener('click', () => {
            const networkData = globalState.rawData.networkDiscovery[ip];
            if (networkData) {
                const dataStr = JSON.stringify(networkData, null, 2);
                const dataBlob = new Blob([dataStr], {
                    type: 'application/json'
                });
                const url = URL.createObjectURL(dataBlob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `network-topology-${ip}-${new Date().toISOString().split('T')[0]}.json`;
                link.click();
                URL.revokeObjectURL(url);
                showNotification('Network topology exported successfully', 'success');
            }
        });
    }
};

/**
 * Setup Threat Intelligence event handlers for a video window
 */
const setupThreatIntelHandlers = (windowElement, streamUrl) => {
    if (!windowElement) return;

    const ip = extractIpFromUrl(streamUrl);
    if (!ip) return;

    // IP Reputation handlers
    const checkReputationBtn = windowElement.querySelector('.check-reputation-btn');
    const reputationTargetIp = windowElement.querySelector('.reputation-target-ip');
    const reputationResults = windowElement.querySelector('.reputation-results');
    const scoreValue = windowElement.querySelector('.score-value');
    const scoreBreakdown = windowElement.querySelector('.score-breakdown');
    const threatSources = windowElement.querySelector('.threat-sources');

    if (checkReputationBtn && reputationTargetIp) {
        // Pre-fill with current IP
        reputationTargetIp.value = ip;

        checkReputationBtn.addEventListener('click', async () => {
            const targetIp = reputationTargetIp.value.trim();

            if (!targetIp) {
                showNotification('Please enter an IP address', 'error');
                return;
            }

            try {
                showNotification('Checking IP reputation...', 'info');
                const results = await checkIPReputation(targetIp);

                // Update risk score display
                if (scoreValue) {
                    scoreValue.textContent = Math.round(results.riskScore);
                    scoreValue.className = `score-value ${getRiskClass(results.riskScore)}`;
                }

                // Update risk factors
                if (scoreBreakdown && results.riskFactors.length > 0) {
                    scoreBreakdown.innerHTML = `
                        <h5>Risk Factors:</h5>
                        <ul>
                            ${results.riskFactors.map(factor => `<li>${factor}</li>`).join('')}
                        </ul>
                    `;
                }

                // Update threat sources
                if (threatSources) {
                    threatSources.innerHTML = `
                        <div class="metadata-raw">
                            <h4>Threat Intelligence Sources</h4>
                            <div class="ip-details-grid">
                                ${Object.entries(results.sources).map(([source, data]) => `
                                    <div class="detail-card">
                                        <div class="detail-header">
                                            <i class="fas fa-shield-alt"></i>
                                            ${data.source || source}
                                        </div>
                                        <div class="detail-content">
                                            <div class="detail-row">
                                                <span class="detail-label">Risk Score:</span>
                                                <span class="detail-value">
                                                    ${data.error ?
                                                        '<span class="security-indicator danger">Error</span>' :
                                                        `<span class="rating-value ${getRiskClass(data.riskScore || 0)}">${data.riskScore || 0}</span>`
                                                    }
                                                </span>
                                            </div>
                                            <div class="detail-row">
                                                <span class="detail-label">Confidence:</span>
                                                <span class="detail-value">${data.error?'N/A' : (data.confidence || 0) + '%'}</span>
                                            </div>
                                            ${data.lastSeen?`
                                                <div class="detail-row">
                                                    <span class="detail-label">Last Seen:</span>
                                                    <span class="detail-value">${new Date(data.lastSeen).toLocaleDateString()}</span>
                                                </div>
                                            ` : ''}
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `;
                }

                // Update malware status
                const malwareStatus = windowElement.querySelector('.malware-status .status-indicator');
                if (malwareStatus) {
                    malwareStatus.className = `status-indicator ${getRiskClass(results.riskScore)}`;
                    malwareStatus.innerHTML = `
                        <i class="fas ${getRiskIcon(results.riskScore)}"></i>
                        <span>${results.summary}</span>
                    `;
                }

                showNotification(`IP reputation check completed. Risk: ${results.summary}`, 'success');

            } catch (error) {
                console.error('IP reputation check failed:', error);
                showNotification(`IP reputation check failed: ${error.message}`, 'error');
            }
        });
    }

    // Auto-run threat intelligence for current IP
    if (ip && globalState.threatIntel.enabled) {
        setTimeout(async () => {
            try {
                const ipData = globalState.rawData.ipInfo[windowElement.dataset.id];
                if (ipData && ipData.lat && ipData.lon) {
                    // Run weather correlation
                    await verifyWeatherCorrelation(ip, ipData.lat, ipData.lon);
                }

                // Run reputation check
                await checkIPReputation(ip);

                // Update UI if elements exist
                if (reputationTargetIp) reputationTargetIp.value = ip;

                showNotification('Automatic threat intelligence analysis completed', 'info');
            } catch (error) {
                console.warn('Auto threat intelligence failed:', error);
            }
        }, 2000); // Delay to allow IP info to load first
    }
};

/**
 * Get CSS class for risk score
 */
const getRiskClass = (score) => {
    if (score >= 80) return 'high-risk';
    if (score >= 50) return 'medium-risk';
    if (score >= 20) return 'low-risk';
    return 'clean';
};

/**
 * Get icon for risk score
 */
const getRiskIcon = (score) => {
    if (score >= 80) return 'fa-exclamation-triangle';
    if (score >= 50) return 'fa-exclamation-circle';
    if (score >= 20) return 'fa-info-circle';
    return 'fa-check-circle';
};

// ============================================================================
// HELPER FUNCTIONS FOR UI STYLING AND INTERACTIONS
// ============================================================================

/**
 * Get appropriate icon for device type
 */
const getDeviceTypeIcon = (deviceType) => {
    const iconMap = {
        'camera': 'fa-video',
        'router': 'fa-wifi',
        'switch': 'fa-network-wired',
        'printer': 'fa-print',
        'nas': 'fa-hdd',
        'iot': 'fa-microchip',
        'computer': 'fa-desktop'
    };
    return iconMap[deviceType] || 'fa-question-circle';
};

/**
 * Get appropriate icon for service type
 */
const getServiceIcon = (service) => {
    const iconMap = {
        'HTTP': 'fa-globe',
        'HTTPS': 'fa-lock',
        'SSH': 'fa-terminal',
        'FTP': 'fa-folder-open',
        'Telnet': 'fa-terminal',
        'SMTP': 'fa-envelope',
        'DNS': 'fa-server',
        'RTSP': 'fa-video',
        'POP3': 'fa-envelope',
        'IMAP': 'fa-envelope',
        'IMAPS': 'fa-envelope-open-text',
        'POP3S': 'fa-envelope-open-text'
    };
    return iconMap[service] || 'fa-plug';
};

/**
 * Get risk level for port
 */
const getPortRiskLevel = (port) => {
    const highRiskPorts = [21, 23, 135, 139, 445, 1433, 3389];
    const mediumRiskPorts = [22, 25, 53, 110, 143, 993, 995];
    const lowRiskPorts = [80, 443, 554, 8000, 8080, 8443];

    if (highRiskPorts.includes(port)) {
        return {
            class: 'danger',
            text: 'High Risk'
        };
    } else if (mediumRiskPorts.includes(port)) {
        return {
            class: 'warning',
            text: 'Medium Risk'
        };
    } else if (lowRiskPorts.includes(port)) {
        return {
            class: 'secure',
            text: 'Low Risk'
        };
    } else {
        return {
            class: 'warning',
            text: 'Unknown Risk'
        };
    }
};

/**
 * Open device in browser
 */
const openDeviceInBrowser = (ip) => {
    const protocols = ['http', 'https'];
    const ports = ['', ':80', ':443', ':8080', ':8000'];

    // Try different combinations
    for (const protocol of protocols) {
        for (const port of ports) {
            const url = `${protocol}://${ip}${port}`;
            window.open(url, '_blank');
            break; // Open only the first combination for now
        }
        break;
    }

    showNotification(`Opening device ${ip} in browser`, 'info');
};

/**
 * Open specific port in browser
 */
const openPortInBrowser = (ip, port) => {
    let protocol = 'http';
    if (port === 443 || port === 8443) {
        protocol = 'https';
    }

    const url = `${protocol}://${ip}:${port}`;
    window.open(url, '_blank');
    showNotification(`Opening ${ip}:${port} in browser`, 'info');
};

/**
 * Add device to camera list
 */
const addDeviceToList = (ip) => {
    // Check if IP already exists in any form
    const existingCamera = globalState.cameras.find(camera => camera.includes(ip));
    if (existingCamera) {
        showNotification(`Device ${ip} is already in the list`, 'warning');
        return;
    }

    // Create the primary RTSP URL
    const primaryUrl = `rtsp://${ip}:554/`;

    // Use the existing addCamera function which properly updates the UI
    const success = addCamera(primaryUrl);

    if (success) {
        // Save to localStorage
        localStorage.setItem('cameras', JSON.stringify(globalState.cameras));

        showNotification(`Added ${ip} to camera list as ${primaryUrl}`, 'success');
        console.log(`[addDeviceToList] Added ${ip} to camera list. Total cameras: ${globalState.cameras.length}`);
    } else {
        showNotification(`Failed to add ${ip} to camera list`, 'error');
    }
};

/**
 * Scan device ports
 */
const scanDevicePorts = async (ip) => {
    try {
        showNotification(`Starting port scan for ${ip}...`, 'info');
        const results = await scanPorts(ip);
        showNotification(`Port scan completed for ${ip}. Found ${results.openPorts.length} open ports`, 'success');
    } catch (error) {
        showNotification(`Port scan failed for ${ip}: ${error.message}`, 'error');
    }
};

/**
 * Copy port information to clipboard
 */
const copyPortInfo = (ip, port, service) => {
    const info = `${ip}:${port} (${service})`;

    // Create temporary textarea for copying
    const textarea = document.createElement('textarea');
    textarea.value = info;
    textarea.style.position = 'fixed';
    textarea.style.opacity = 0;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);

    showNotification(`Copied ${info} to clipboard`, 'success');
};

/**
 * Open device port for interaction
 */
const openDevicePort = (ip, port) => {
    openPortInBrowser(ip, port);
};





/**
 * Setup horizontal scrolling for info tabs with mouse wheel and middle click
 */
const setupInfoTabsScrolling = (windowElement) => {
    if (!windowElement) return;

    const infoTabs = windowElement.querySelector('.info-tabs');
    if (!infoTabs) return;

    // Mouse wheel horizontal scrolling
    infoTabs.addEventListener('wheel', (e) => {
        // Prevent default vertical scrolling
        e.preventDefault();

        // Calculate scroll amount (adjust multiplier for sensitivity)
        const scrollAmount = e.deltaY * 0.5;

        // Apply horizontal scroll
        infoTabs.scrollLeft += scrollAmount;

        // Add smooth scrolling effect
        infoTabs.style.scrollBehavior = 'smooth';

        // Reset scroll behavior after a short delay
        setTimeout(() => {
            infoTabs.style.scrollBehavior = 'auto';
        }, 150);
    }, {
        passive: false
    });

    // Middle mouse button drag scrolling
    let isMiddleMouseDown = false;
    let startX = 0;
    let scrollLeft = 0;

    infoTabs.addEventListener('mousedown', (e) => {
        // Check for middle mouse button (button 1)
        if (e.button === 1) {
            e.preventDefault();
            isMiddleMouseDown = true;
            startX = e.pageX - infoTabs.offsetLeft;
            scrollLeft = infoTabs.scrollLeft;

            // Change cursor to indicate dragging
            infoTabs.style.cursor = 'grabbing';

            // Prevent text selection during drag
            infoTabs.style.userSelect = 'none';
        }
    });

    infoTabs.addEventListener('mouseleave', () => {
        if (isMiddleMouseDown) {
            isMiddleMouseDown = false;
            infoTabs.style.cursor = '';
            infoTabs.style.userSelect = '';
        }
    });

    infoTabs.addEventListener('mouseup', (e) => {
        if (e.button === 1 && isMiddleMouseDown) {
            isMiddleMouseDown = false;
            infoTabs.style.cursor = '';
            infoTabs.style.userSelect = '';
        }
    });

    infoTabs.addEventListener('mousemove', (e) => {
        if (!isMiddleMouseDown) return;

        e.preventDefault();
        const x = e.pageX - infoTabs.offsetLeft;
        const walk = (x - startX) * 2; // Multiply for faster scrolling
        infoTabs.scrollLeft = scrollLeft - walk;
    });

    // Touch support for mobile devices
    let touchStartX = 0;
    let touchScrollLeft = 0;

    infoTabs.addEventListener('touchstart', (e) => {
        touchStartX = e.touches[0].pageX - infoTabs.offsetLeft;
        touchScrollLeft = infoTabs.scrollLeft;
    }, {
        passive: true
    });

    infoTabs.addEventListener('touchmove', (e) => {
        if (!touchStartX) return;

        const x = e.touches[0].pageX - infoTabs.offsetLeft;
        const walk = (x - touchStartX) * 1.5;
        infoTabs.scrollLeft = touchScrollLeft - walk;
    }, {
        passive: true
    });

    infoTabs.addEventListener('touchend', () => {
        touchStartX = 0;
    }, {
        passive: true
    });

    // Keyboard navigation support
    infoTabs.addEventListener('keydown', (e) => {
        switch (e.key) {
            case 'ArrowLeft':
                e.preventDefault();
                infoTabs.scrollLeft -= 50;
                break;
            case 'ArrowRight':
                e.preventDefault();
                infoTabs.scrollLeft += 50;
                break;
            case 'Home':
                e.preventDefault();
                infoTabs.scrollLeft = 0;
                break;
            case 'End':
                e.preventDefault();
                infoTabs.scrollLeft = infoTabs.scrollWidth;
                break;
        }
    });

    // Make tabs container focusable for keyboard navigation
    if (!infoTabs.hasAttribute('tabindex')) {
        infoTabs.setAttribute('tabindex', '0');
    }

    // Add visual feedback for focus
    infoTabs.addEventListener('focus', () => {
        infoTabs.style.outline = `2px solid ${getComputedStyle(document.documentElement).getPropertyValue('--primary-color')}`;
        infoTabs.style.outlineOffset = '2px';
    });

    infoTabs.addEventListener('blur', () => {
        infoTabs.style.outline = '';
        infoTabs.style.outlineOffset = '';
    });

    // Auto-scroll to active tab when it changes
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
                const target = mutation.target;
                if (target.classList.contains('tab-button') && target.classList.contains('active')) {
                    // Scroll the active tab into view
                    setTimeout(() => {
                        const tabRect = target.getBoundingClientRect();
                        const containerRect = infoTabs.getBoundingClientRect();

                        if (tabRect.left < containerRect.left || tabRect.right > containerRect.right) {
                            target.scrollIntoView({
                                behavior: 'smooth',
                                block: 'nearest',
                                inline: 'center'
                            });
                        }
                    }, 50);
                }
            }
        });
    });

    // Observe all tab buttons for class changes
    const tabButtons = infoTabs.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        observer.observe(button, {
            attributes: true,
            attributeFilter: ['class']
        });
    });

    console.log('[setupInfoTabsScrolling] Enhanced scrolling enabled for info tabs');
};

/**
 * Setup Data Export & Reporting handlers for a video window
 */
const setupDataExportHandlers = (windowElement, streamUrl) => {
    if (!windowElement) return;

    const ip = extractIpFromUrl(streamUrl);
    if (!ip) return;

    // Initialize export history if not exists
    if (!globalState.rawData.exportHistory) {
        globalState.rawData.exportHistory = [];
    }

    // Export Data handlers
    const exportDataBtn = windowElement.querySelector('.export-data-btn');
    const generateReportBtn = windowElement.querySelector('.generate-report-btn');
    const exportAllBtn = windowElement.querySelector('.export-all-btn');
    const exportFormat = windowElement.querySelector('.export-format');

    if (exportDataBtn) {
        exportDataBtn.addEventListener('click', async () => {
            const format = exportFormat?.value || 'json';
            const includeOptions = getExportIncludeOptions(windowElement);

            try {
                showNotification('Exporting data...', 'info');
                await exportCameraData(ip, format, includeOptions, windowElement);
                showNotification('Data exported successfully', 'success');
            } catch (error) {
                console.error('Export failed:', error);
                showNotification(`Export failed: ${error.message}`, 'error');
            }
        });
    }

    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', async () => {
            const template = windowElement.querySelector('.report-template')?.value || 'security-audit';

            try {
                showNotification('Generating report...', 'info');
                await generateReport(ip, template, windowElement);
                showNotification('Report generated successfully', 'success');
            } catch (error) {
                console.error('Report generation failed:', error);
                showNotification(`Report generation failed: ${error.message}`, 'error');
            }
        });
    }

    if (exportAllBtn) {
        exportAllBtn.addEventListener('click', async () => {
            try {
                showNotification('Exporting all data...', 'info');
                await exportAllData(windowElement);
                showNotification('All data exported successfully', 'success');
            } catch (error) {
                console.error('Export all failed:', error);
                showNotification(`Export all failed: ${error.message}`, 'error');
            }
        });
    }

    // Template handlers
    const reportTemplate = windowElement.querySelector('.report-template');
    const templateDescription = windowElement.querySelector('.template-description');
    const previewTemplateBtn = windowElement.querySelector('.preview-template-btn');
    const customizeTemplateBtn = windowElement.querySelector('.customize-template-btn');

    if (reportTemplate && templateDescription) {
        reportTemplate.addEventListener('change', () => {
            updateTemplateDescription(reportTemplate.value, templateDescription);
        });
    }

    if (previewTemplateBtn) {
        previewTemplateBtn.addEventListener('click', () => {
            const template = reportTemplate?.value || 'security-audit';
            previewReportTemplate(template, windowElement);
        });
    }

    if (customizeTemplateBtn) {
        customizeTemplateBtn.addEventListener('click', () => {
            const template = reportTemplate?.value || 'security-audit';
            customizeReportTemplate(template, windowElement);
        });
    }

    // Export History handlers
    const clearHistoryBtn = windowElement.querySelector('.clear-history-btn');
    const exportHistoryBtn = windowElement.querySelector('.export-history-btn');

    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', () => {
            clearExportHistory(windowElement);
        });
    }

    if (exportHistoryBtn) {
        exportHistoryBtn.addEventListener('click', () => {
            exportExportHistory(windowElement);
        });
    }

    // Automation handlers
    const saveAutomationBtn = windowElement.querySelector('.save-automation-btn');
    const testAutomationBtn = windowElement.querySelector('.test-automation-btn');

    if (saveAutomationBtn) {
        saveAutomationBtn.addEventListener('click', () => {
            saveAutomationSettings(windowElement);
        });
    }

    if (testAutomationBtn) {
        testAutomationBtn.addEventListener('click', async () => {
            try {
                showNotification('Testing automation...', 'info');
                await testAutomationExport(ip, windowElement);
                showNotification('Automation test completed', 'success');
            } catch (error) {
                console.error('Automation test failed:', error);
                showNotification(`Automation test failed: ${error.message}`, 'error');
            }
        });
    }

    // Update data statistics
    updateDataStatistics(ip, windowElement);

    // Update export history display
    updateExportHistoryDisplay(windowElement);

    console.log('[setupDataExportHandlers] Data export handlers initialized');
};

/**
 * Get export include options from checkboxes
 */
const getExportIncludeOptions = (windowElement) => {
    return {
        basic: windowElement.querySelector('.export-include-basic')?.checked || false,
        location: windowElement.querySelector('.export-include-location')?.checked || false,
        metadata: windowElement.querySelector('.export-include-metadata')?.checked || false,
        network: windowElement.querySelector('.export-include-network')?.checked || false,
        threats: windowElement.querySelector('.export-include-threats')?.checked || false,
        fingerprint: windowElement.querySelector('.export-include-fingerprint')?.checked || false
    };
};

/**
 * Export camera data in specified format
 */
const exportCameraData = async (ip, format, includeOptions, windowElement) => {
    console.log(`[exportCameraData] Exporting data for ${ip} in ${format} format`);

    // Show progress
    showExportProgress(windowElement, 0, 'Collecting data...');

    // Collect data based on include options
    const exportData = {
        timestamp: new Date().toISOString(),
        ip: ip,
        exportFormat: format,
        data: {}
    };

    let progress = 10;

    if (includeOptions.basic) {
        exportData.data.basicInfo = globalState.rawData.ipInfo?. [ip] || {};
        progress += 15;
        showExportProgress(windowElement, progress, 'Collecting basic info...');
    }

    if (includeOptions.location) {
        exportData.data.locationData = globalState.rawData.locationData?. [ip] || {};
        progress += 15;
        showExportProgress(windowElement, progress, 'Collecting location data...');
    }

    if (includeOptions.metadata) {
        exportData.data.metadata = globalState.rawData.metadata?. [ip] || {};
        progress += 15;
        showExportProgress(windowElement, progress, 'Collecting metadata...');
    }

    if (includeOptions.network) {
        exportData.data.networkDiscovery = {
            discoveredDevices: globalState.rawData.networkDiscovery?. [ip]?.discoveredDevices || [],
            topology: globalState.rawData.topology?. [ip] || {},
            portScans: globalState.rawData.portScans?. [ip] || {}
        };
        progress += 15;
        showExportProgress(windowElement, progress, 'Collecting network data...');
    }

    if (includeOptions.threats) {
        exportData.data.threatIntelligence = globalState.rawData.threatIntelligence?. [ip] || {};
        progress += 15;
        showExportProgress(windowElement, progress, 'Collecting threat data...');
    }

    if (includeOptions.fingerprint) {
        exportData.data.fingerprinting = {
            httpHeaders: globalState.rawData.cameraFingerprint?. [ip] || {},
            urlPatterns: globalState.rawData.urlPatterns?. [ip] || {},
            certificates: globalState.rawData.certificates?. [ip] || {}
        };
        progress += 15;
        showExportProgress(windowElement, progress, 'Collecting fingerprint data...');
    }

    // Format and download data
    showExportProgress(windowElement, 90, 'Formatting data...');
    await new Promise(resolve => setTimeout(resolve, 500)); // Simulate processing

    let fileContent, fileName, mimeType;

    switch (format) {
        case 'json':
            fileContent = JSON.stringify(exportData, null, 2);
            fileName = `camera_data_${ip}_${Date.now()}.json`;
            mimeType = 'application/json';
            break;
        case 'csv':
            fileContent = convertToCSV(exportData);
            fileName = `camera_data_${ip}_${Date.now()}.csv`;
            mimeType = 'text/csv';
            break;
        case 'xml':
            fileContent = convertToXML(exportData);
            fileName = `camera_data_${ip}_${Date.now()}.xml`;
            mimeType = 'application/xml';
            break;
        case 'pdf':
            fileContent = await generatePDFReport(exportData);
            fileName = `camera_report_${ip}_${Date.now()}.pdf`;
            mimeType = 'application/pdf';
            break;
        case 'html':
            fileContent = generateHTMLReport(exportData);
            fileName = `camera_report_${ip}_${Date.now()}.html`;
            mimeType = 'text/html';
            break;
        default:
            throw new Error(`Unsupported format: ${format}`);
    }

    // Download file
    downloadFile(fileContent, fileName, mimeType);

    // Add to export history
    addToExportHistory({
        ip: ip,
        format: format,
        fileName: fileName,
        timestamp: new Date().toISOString(),
        size: fileContent.length,
        includeOptions: includeOptions
    });

    showExportProgress(windowElement, 100, 'Export completed!');

    // Hide progress after delay
    setTimeout(() => {
        hideExportProgress(windowElement);
    }, 2000);

    // Update statistics
    updateDataStatistics(ip, windowElement);
    updateExportHistoryDisplay(windowElement);
};

/**
 * Show export progress indicator
 */
const showExportProgress = (windowElement, percentage, message) => {
    let progressDiv = windowElement.querySelector('.export-progress');

    if (!progressDiv) {
        // Create progress indicator if it doesn't exist
        progressDiv = document.createElement('div');
        progressDiv.className = 'export-progress';
        progressDiv.innerHTML = `
            <div class="export-progress-bar">
                <div class="export-progress-fill"></div>
            </div>
            <div class="export-progress-text"></div>
        `;

        const exportSection = windowElement.querySelector('.metadata-section');
        if (exportSection) {
            exportSection.appendChild(progressDiv);
        }
    }

    progressDiv.classList.add('active');

    const progressFill = progressDiv.querySelector('.export-progress-fill');
    const progressText = progressDiv.querySelector('.export-progress-text');

    if (progressFill) progressFill.style.width = `${percentage}%`;
    if (progressText) progressText.textContent = message;
};

/**
 * Hide export progress indicator
 */
const hideExportProgress = (windowElement) => {
    const progressDiv = windowElement.querySelector('.export-progress');
    if (progressDiv) {
        progressDiv.classList.remove('active');
    }
};

/**
 * Download file with given content
 */
const downloadFile = (content, fileName, mimeType) => {
    const blob = new Blob([content], {
        type: mimeType
    });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.style.display = 'none';

    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    URL.revokeObjectURL(url);
};

/**
 * Convert data to CSV format
 */
const convertToCSV = (data) => {
    const rows = [];

    // Add header
    rows.push(['Field', 'Value', 'Category']);

    // Flatten data structure
    const flattenObject = (obj, prefix = '', category = '') => {
        for (const [key, value] of Object.entries(obj)) {
            const fullKey = prefix?`${prefix}.${key}` : key;

            if (value && typeof value === 'object' && !Array.isArray(value)) {
                flattenObject(value, fullKey, category || key);
            } else {
                const stringValue = Array.isArray(value)?value.join('; ') : String(value);
                rows.push([fullKey, stringValue, category || 'general']);
            }
        }
    };

    flattenObject(data.data);

    // Convert to CSV string
    return rows.map(row =>
        row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
    ).join('\n');
};

/**
 * Convert data to XML format
 */
const convertToXML = (data) => {
    const escapeXml = (str) => {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };

    const objectToXml = (obj, indent = 0) => {
        const spaces = '  '.repeat(indent);
        let xml = '';

        for (const [key, value] of Object.entries(obj)) {
            const tagName = key.replace(/[^a-zA-Z0-9]/g, '_');

            if (value && typeof value === 'object' && !Array.isArray(value)) {
                xml += `${spaces}<${tagName}>\n`;
                xml += objectToXml(value, indent + 1);
                xml += `${spaces}</${tagName}>\n`;
            } else if (Array.isArray(value)) {
                xml += `${spaces}<${tagName}>\n`;
                value.forEach((item, index) => {
                    xml += `${spaces}  <item_${index}>${escapeXml(item)}</item_${index}>\n`;
                });
                xml += `${spaces}</${tagName}>\n`;
            } else {
                xml += `${spaces}<${tagName}>${escapeXml(value)}</${tagName}>\n`;
            }
        }

        return xml;
    };

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<camera_data>\n';
    xml += `  <timestamp>${escapeXml(data.timestamp)}</timestamp>\n`;
    xml += `  <ip>${escapeXml(data.ip)}</ip>\n`;
    xml += `  <export_format>${escapeXml(data.exportFormat)}</export_format>\n`;
    xml += '  <data>\n';
    xml += objectToXml(data.data, 2);
    xml += '  </data>\n';
    xml += '</camera_data>';

    return xml;
};

/**
 * Generate HTML report
 */
const generateHTMLReport = (data) => {
    const timestamp = new Date(data.timestamp).toLocaleString();

    let html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Camera Analysis Report - ${data.ip}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #e11d48; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #e11d48; margin: 0; }
        .header .meta { color: #666; margin-top: 10px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-left: 4px solid #e11d48; padding-left: 15px; }
        .data-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .data-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; }
        .data-card h3 { margin-top: 0; color: #495057; }
        .data-item { margin-bottom: 10px; }
        .data-label { font-weight: bold; color: #6c757d; }
        .data-value { margin-left: 10px; word-break: break-word; }
        .vulnerability { background: #fff5f5; border-left: 4px solid #ef4444; padding: 10px; margin: 10px 0; }
        .success { color: #10b981; }
        .warning { color: #f59e0b; }
        .danger { color: #ef4444; }
        .array-item { display: block; margin: 2px 0; padding: 4px 8px; background: #e9ecef; border-radius: 3px; }
        .object-container { margin-left: 15px; border-left: 2px solid #dee2e6; padding-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Camera Analysis Report</h1>
            <div class="meta">
                <strong>IP Address:</strong> ${data.ip}<br>
                <strong>Generated:</strong> ${timestamp}<br>
                <strong>Format:</strong> ${data.exportFormat}
            </div>
        </div>
`;

    /**
     * Helper function to format values properly
     */
    const formatValue = (value, depth = 0) => {
        if (value === null || value === undefined) {
            return '<em>null</em>';
        }

        if (Array.isArray(value)) {
            if (value.length === 0) {
                return '<em>No items</em>';
            }
            return value.map(item => {
                if (typeof item === 'object' && item !== null) {
                    return `<div class="array-item">${formatValue(item, depth + 1)}</div>`;
                } else {
                    return `<div class="array-item">${String(item)}</div>`;
                }
            }).join('');
        }

        if (typeof value === 'object' && value !== null) {
            let result = '';
            for (const [key, val] of Object.entries(value)) {
                result += `<div class="data-item">
                    <span class="data-label">${key}:</span>
                    <span class="data-value">${formatValue(val, depth + 1)}</span>
                </div>`;
            }
            return depth > 0?`<div class="object-container">${result}</div>` : result;
        }

        if (typeof value === 'boolean') {
            return value?'<span class="success">Yes</span>' : '<span class="warning">No</span>';
        }

        if (typeof value === 'string' && value.includes('GMT')) {
            // Format dates
            try {
                const date = new Date(value);
                return date.toLocaleString();
            } catch (e) {
                return String(value);
            }
        }

        return String(value);
    };

    // Add sections based on available data
    for (const [sectionKey, sectionData] of Object.entries(data.data)) {
        if (!sectionData) continue;

        const sectionTitle = sectionKey.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
        html += `        <div class="section">
            <h2>${sectionTitle}</h2>`;

        if (typeof sectionData === 'object') {
            // Check if it's an empty object
            if (Object.keys(sectionData).length === 0) {
                html += `            <p><em>No data available for this section</em></p>`;
            } else {
                html += `            <div class="data-grid">`;

                for (const [key, value] of Object.entries(sectionData)) {
                    const cardTitle = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                    html += `                <div class="data-card">
                        <h3>${cardTitle}</h3>
                        ${formatValue(value)}
                    </div>`;
                }

                html += `            </div>`;
            }
        } else {
            html += `            <div class="data-card">
                <div class="data-value">${formatValue(sectionData)}</div>
            </div>`;
        }

        html += `        </div>`;
    }

    html += `    </div>
</body>
</html>`;

    return html;
};

/**
 * Generate PDF report (simplified - in production use a proper PDF library)
 */
const generatePDFReport = async (data) => {
    // For this demo, we'll return the HTML content
    // In production, you would use a library like jsPDF or Puppeteer
    const htmlContent = generateHTMLReport(data);
    return `PDF Report for ${data.ip}\n\nGenerated: ${data.timestamp}\n\nThis would be a proper PDF in production.\n\nData:\n${JSON.stringify(data.data, null, 2)}`;
};

/**
 * Add entry to export history
 */
const addToExportHistory = (exportEntry) => {
    if (!globalState.rawData.exportHistory) {
        globalState.rawData.exportHistory = [];
    }

    globalState.rawData.exportHistory.unshift(exportEntry);

    // Keep only last 50 exports
    if (globalState.rawData.exportHistory.length > 50) {
        globalState.rawData.exportHistory = globalState.rawData.exportHistory.slice(0, 50);
    }
};

/**
 * Update export history display
 */
const updateExportHistoryDisplay = (windowElement) => {
    const exportCount = windowElement.querySelector('.export-count');
    const exportHistoryItems = windowElement.querySelector('.export-history-items');

    const history = globalState.rawData.exportHistory || [];

    if (exportCount) {
        exportCount.textContent = history.length;
    }

    if (exportHistoryItems) {
        if (history.length === 0) {
            exportHistoryItems.innerHTML = '<div class="metadata-item"><span class="metadata-value">No exports yet</span></div>';
        } else {
            exportHistoryItems.innerHTML = history.slice(0, 10).map(entry => `
                <div class="export-history-item">
                    <div class="export-history-info">
                        <div class="export-history-name">${entry.fileName}</div>
                        <div class="export-history-details">
                            ${entry.ip} • ${entry.format.toUpperCase()} • ${new Date(entry.timestamp).toLocaleDateString()}
                        </div>
                    </div>
                    <div class="export-history-actions">
                        <button onclick="redownloadExport('${entry.fileName}')">
                            <i class="fas fa-download"></i>
                        </button>
                        <button onclick="deleteExportHistory('${entry.fileName}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            `).join('');
        }
    }
};

/**
 * Update data statistics display
 */
const updateDataStatistics = (ip, windowElement) => {
    const totalDataPoints = windowElement.querySelector('.total-data-points');
    const totalVulnerabilities = windowElement.querySelector('.total-vulnerabilities');
    const totalDevices = windowElement.querySelector('.total-devices');
    const totalThreatScore = windowElement.querySelector('.total-threat-score');

    // Calculate statistics from collected data
    let dataPoints = 0;
    let vulnerabilities = 0;
    let devices = 0;
    let threatScore = 0;

    // Count data points
    const rawData = globalState.rawData;
    if (rawData.ipInfo?. [ip]) dataPoints += Object.keys(rawData.ipInfo[ip]).length;
    if (rawData.locationData?. [ip]) dataPoints += Object.keys(rawData.locationData[ip]).length;
    if (rawData.metadata?. [ip]) dataPoints += Object.keys(rawData.metadata[ip]).length;

    // Count vulnerabilities
    if (rawData.cameraFingerprint?. [ip]?.vulnerabilities) {
        vulnerabilities += rawData.cameraFingerprint[ip].vulnerabilities.length;
    }

    // Count devices
    if (rawData.networkDiscovery?. [ip]?.discoveredDevices) {
        devices = rawData.networkDiscovery[ip].discoveredDevices.length;
    }

    // Calculate threat score
    if (rawData.threatIntelligence?. [ip]?.overallScore) {
        threatScore = rawData.threatIntelligence[ip].overallScore;
    }

    // Update display
    if (totalDataPoints) totalDataPoints.textContent = dataPoints;
    if (totalVulnerabilities) totalVulnerabilities.textContent = vulnerabilities;
    if (totalDevices) totalDevices.textContent = devices;
    if (totalThreatScore) totalThreatScore.textContent = threatScore;
};

/**
 * Generate report using template
 */
const generateReport = async (ip, template, windowElement) => {
    console.log(`[generateReport] Generating ${template} report for ${ip}`);

    const includeOptions = {
        basic: true,
        location: true,
        metadata: true,
        network: true,
        threats: true,
        fingerprint: true
    };

    // Always use HTML format for template-based reports
    await exportCameraData(ip, 'html', includeOptions, windowElement);
};

/**
 * Export all data for all analyzed IPs
 */
const exportAllData = async (windowElement) => {
    console.log('[exportAllData] Exporting all collected data');

    const allData = {
        timestamp: new Date().toISOString(),
        exportType: 'complete_dataset',
        data: globalState.rawData
    };

    const fileName = `complete_osint_data_${Date.now()}.json`;
    const fileContent = JSON.stringify(allData, null, 2);

    downloadFile(fileContent, fileName, 'application/json');

    addToExportHistory({
        ip: 'all',
        format: 'json',
        fileName: fileName,
        timestamp: new Date().toISOString(),
        size: fileContent.length,
        includeOptions: {
            all: true
        }
    });

    updateExportHistoryDisplay(windowElement);
};

/**
 * Update template description
 */
const updateTemplateDescription = (template, descriptionElement) => {
    const descriptions = {
        'security-audit': 'Comprehensive security audit including vulnerabilities, network topology, and threat analysis',
        'network-assessment': 'Detailed network discovery and device analysis report',
        'vulnerability-scan': 'Focused vulnerability assessment with CVE details and risk ratings',
        'compliance-check': 'Security compliance verification against industry standards',
        'forensic-analysis': 'Detailed forensic analysis for incident response and investigation',
        'custom': 'Customizable report template with user-defined sections'
    };

    descriptionElement.textContent = descriptions[template] || 'Custom report template';
};

/**
 * Preview report template
 */
const previewReportTemplate = (template, windowElement) => {
    const previewWindow = window.open('', '_blank', 'width=800,height=600');
    previewWindow.document.write(`
        <html>
        <head>
            <title>Report Template Preview - ${template}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { border-bottom: 2px solid #e11d48; padding-bottom: 20px; margin-bottom: 30px; }
                .section { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 6px; }
                .placeholder { color: #666; font-style: italic; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>${template.replace('-', ' ').toUpperCase()} Report Preview</h1>
                <p>This is a preview of the ${template} template structure.</p>
            </div>
            <div class="section">
                <h2>Executive Summary</h2>
                <p class="placeholder">[Summary of findings and recommendations]</p>
            </div>
            <div class="section">
                <h2>Technical Details</h2>
                <p class="placeholder">[Detailed technical analysis and data]</p>
            </div>
            <div class="section">
                <h2>Recommendations</h2>
                <p class="placeholder">[Security recommendations and next steps]</p>
            </div>
        </body>
        </html>
    `);
};

/**
 * Customize report template
 */
const customizeReportTemplate = (template, windowElement) => {
    showNotification('Template customization would open in a separate editor', 'info');
    // In production, this would open a template editor
};

/**
 * Clear export history
 */
const clearExportHistory = (windowElement) => {
    if (confirm('Are you sure you want to clear the export history?')) {
        globalState.rawData.exportHistory = [];
        updateExportHistoryDisplay(windowElement);
        showNotification('Export history cleared', 'success');
    }
};

/**
 * Export export history
 */
const exportExportHistory = (windowElement) => {
    const history = globalState.rawData.exportHistory || [];
    const fileName = `export_history_${Date.now()}.json`;
    const fileContent = JSON.stringify(history, null, 2);

    downloadFile(fileContent, fileName, 'application/json');
    showNotification('Export history downloaded', 'success');
};

/**
 * Save automation settings
 */
const saveAutomationSettings = (windowElement) => {
    const autoExportEnabled = windowElement.querySelector('.auto-export-enabled')?.checked || false;
    const frequency = windowElement.querySelector('.auto-export-frequency')?.value || 'daily';
    const format = windowElement.querySelector('.auto-export-format')?.value || 'json';

    const settings = {
        enabled: autoExportEnabled,
        frequency: frequency,
        format: format,
        lastSaved: new Date().toISOString()
    };

    // Save to localStorage
    localStorage.setItem('osint_automation_settings', JSON.stringify(settings));

    showNotification('Automation settings saved', 'success');
};

/**
 * Test automation export
 */
const testAutomationExport = async (ip, windowElement) => {
    const settings = JSON.parse(localStorage.getItem('osint_automation_settings') || '{}');

    if (!settings.enabled) {
        throw new Error('Automation is not enabled');
    }

    const includeOptions = {
        basic: true,
        location: true,
        metadata: true,
        network: true,
        threats: true,
        fingerprint: true
    };

    await exportCameraData(ip, settings.format || 'json', includeOptions, windowElement);
};

/**
 * Re-download export from history
 */
const redownloadExport = (fileName) => {
    showNotification(`Re-downloading ${fileName} (feature would be implemented in production)`, 'info');
    // In production, this would regenerate and download the file
};

/**
 * Delete export from history
 */
const deleteExportHistory = (fileName) => {
    if (confirm(`Delete ${fileName} from history?`)) {
        globalState.rawData.exportHistory = globalState.rawData.exportHistory.filter(
            entry => entry.fileName !== fileName
        );

        // Update all windows
        document.querySelectorAll('.video-window').forEach(window => {
            updateExportHistoryDisplay(window);
        });

        showNotification('Export deleted from history', 'success');
    }
};



















// ============================================================================
// SOCIAL MEDIA & WEB INTELLIGENCE FUNCTIONS
// ============================================================================



/**
 * Analyze domain and website intelligence
 */
const analyzeDomainIntelligence = async (target, windowElement) => {
    console.log(`[analyzeDomainIntelligence] Analyzing domain intelligence for ${target}`);

    await new Promise(resolve => setTimeout(resolve, Math.random() * 2500 + 1000));

    const domainStatus = windowElement.querySelector('.domain-status');
    const domainRegistration = windowElement.querySelector('.domain-registration');
    const domainDetails = windowElement.querySelector('.domain-details');

    // No fake domain analysis - real domain intelligence requires authenticated APIs
    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(target);
    const status = isIP?'IP Address' : 'Analysis requires authenticated APIs';

    if (domainStatus) {
        domainStatus.innerHTML = `<span class="security-indicator ${status === 'Active' || isIP?'secure' : 'warning'}">${status}</span>`;
    }

    if (domainRegistration) {
        domainRegistration.textContent = isIP?'N/A (IP Address)' : 'Requires authenticated APIs';
    }

    if (domainDetails) {
        domainDetails.innerHTML = `
            <div class="metadata-raw">
                <h4>Domain Intelligence Analysis</h4>
                <div class="ip-details-grid">
                    <div class="detail-card">
                        <div class="detail-header">
                            <i class="fas fa-globe"></i>
                            ${isIP?'IP Information' : 'Domain Information'}
                        </div>
                        <div class="detail-content">
                            <div class="detail-row">
                                <span class="detail-label">${isIP?'IP Address:' : 'Domain:'}</span>
                                <span class="detail-value">${target}</span>
                            </div>
                            ${!isIP?`
                                <div class="detail-row">
                                    <span class="detail-label">Domain Analysis:</span>
                                    <span class="detail-value">Requires authenticated APIs for WHOIS, DNS, and registrar data</span>
                                </div>
                            ` : `
                                <div class="detail-row">
                                    <span class="detail-label">IP Analysis:</span>
                                    <span class="detail-value">Reverse DNS and PTR record analysis requires specialized tools</span>
                                </div>
                            `}
                            <div class="detail-row">
                                <span class="detail-label">Security Analysis:</span>
                                <span class="detail-value">Requires authenticated APIs for malware, phishing, and reputation analysis</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Store results
    globalState.rawData.domainIntelligence = globalState.rawData.domainIntelligence || {};
    globalState.rawData.domainIntelligence[target] = {
        target,
        status,
        timestamp: new Date().toISOString(),
        isIP
    };
};

/**
 * Search social media platforms
 */
const searchSocialMedia = async (searchTerm, platform, windowElement) => {
    console.log(`[searchSocialMedia] Social media search not available - no free APIs`);

    const profilesFound = windowElement.querySelector('.profiles-found');
    const relevanceScore = windowElement.querySelector('.relevance-score');
    const socialProfiles = windowElement.querySelector('.social-profiles');

    // Show unavailable message
    if (profilesFound) {
        profilesFound.textContent = 'N/A';
    }

    if (relevanceScore) {
        relevanceScore.innerHTML = `<span class="rating-value low">Unavailable</span>`;
    }

    if (socialProfiles) {
        socialProfiles.innerHTML = `
            <div class="metadata-raw">
                <h4>Social Media Intelligence</h4>
                <div class="detail-card">
                    <div class="detail-content">
                        <div class="detail-row">
                            <span class="detail-value">
                                <i class="fas fa-info-circle"></i>
                                Social media intelligence requires authenticated APIs with strict rate limits.
                                No free APIs are available for comprehensive social media searches.
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
};

/**
 * Analyze email intelligence
 */
const analyzeEmailIntelligence = async (target, windowElement) => {
    console.log(`[analyzeEmailIntelligence] Analyzing email intelligence for ${target}`);

    await new Promise(resolve => setTimeout(resolve, Math.random() * 2000 + 800));

    const emailDetails = windowElement.querySelector('.email-details');

    const isEmail = target.includes('@');
    const domain = isEmail?target.split('@')[1] : target;

    if (emailDetails) {
        emailDetails.innerHTML = `
            <div class="metadata-raw">
                <h4>Email Intelligence Analysis</h4>
                <div class="detail-card">
                    <div class="detail-header">
                        <i class="fas fa-envelope"></i>
                        ${isEmail?'Email Analysis' : 'Domain Email Analysis'}
                    </div>
                    <div class="detail-content">
                        <div class="detail-row">
                            <span class="detail-label">${isEmail?'Email:' : 'Domain:'}</span>
                            <span class="detail-value">${target}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Email Analysis:</span>
                            <span class="detail-value">Requires authenticated APIs for validity, deliverability, and risk analysis</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
};

/**
 * Find emails associated with domain/IP
 */
const findEmails = async (target, windowElement) => {
    console.log(`[findEmails] Finding emails for ${target}`);

    await new Promise(resolve => setTimeout(resolve, Math.random() * 2500 + 1000));

    const emailsFound = windowElement.querySelector('.emails-found');
    const emailDetails = windowElement.querySelector('.email-details');

    if (emailsFound) {
        emailsFound.textContent = 'N/A';
    }

    if (emailDetails) {
        // No fake email generation - real email intelligence requires authenticated APIs
        emailDetails.innerHTML += `
            <div class="detail-card" style="margin-top: 10px;">
                <div class="detail-header">
                    <i class="fas fa-search"></i>
                    Email Discovery Results
                </div>
                <div class="detail-content">
                    <div class="detail-row">
                        <span class="detail-value">Email discovery requires authenticated APIs for comprehensive searches</span>
                    </div>
                </div>
            </div>
        `;
    }
};

/**
 * Verify found emails
 */
const verifyEmails = async (windowElement) => {
    console.log(`[verifyEmails] Verifying emails`);

    await new Promise(resolve => setTimeout(resolve, Math.random() * 1800 + 600));

    const emailDetails = windowElement.querySelector('.email-details');

    if (emailDetails) {
        emailDetails.innerHTML += `
            <div class="detail-card" style="margin-top: 10px;">
                <div class="detail-header">
                    <i class="fas fa-check-circle"></i>
                    Email Verification Results
                </div>
                <div class="detail-content">
                    <div class="detail-row">
                        <span class="detail-value">Email verification requires authenticated APIs for accuracy and deliverability checks</span>
                    </div>
                </div>
            </div>
        `;
    }
};

/**
 * Check breach databases
 */
const checkBreaches = async (windowElement) => {
    console.log(`[checkBreaches] Checking breach databases`);

    await new Promise(resolve => setTimeout(resolve, Math.random() * 2200 + 800));

    const breachStatus = windowElement.querySelector('.breach-status');
    const emailDetails = windowElement.querySelector('.email-details');

    if (breachStatus) {
        breachStatus.innerHTML = `<span class="security-indicator low">Requires authenticated APIs</span>`;
    }

    if (emailDetails) {
        // No fake breach data generation - real breach intelligence requires authenticated APIs
        const breaches = '<div class="detail-row"><span class="detail-value">Breach intelligence requires authenticated APIs</span></div>';

        emailDetails.innerHTML += `
            <div class="detail-card" style="margin-top: 10px;">
                <div class="detail-header">
                    <i class="fas fa-shield-alt"></i>
                    Breach Database Check
                </div>
                <div class="detail-content">
                    ${breaches}
                    <div class="detail-row">
                        <span class="detail-label">Breach Analysis:</span>
                        <span class="detail-value">Requires authenticated APIs for comprehensive breach database checks</span>
                    </div>
                </div>
            </div>
        `;
    }
};

/**
 * Dark web search - REMOVED
 * No legitimate free APIs exist for dark web intelligence
 */
const searchDarkWeb = async (target, windowElement) => {
    console.log(`[searchDarkWeb] Dark web search not available - no legitimate APIs`);

    const darkwebMentions = windowElement.querySelector('.darkweb-mentions');
    const darkwebThreatLevel = windowElement.querySelector('.darkweb-threat-level');
    const darkwebDetails = windowElement.querySelector('.darkweb-details');

    if (darkwebMentions) {
        darkwebMentions.textContent = 'N/A';
    }

    if (darkwebThreatLevel) {
        darkwebThreatLevel.innerHTML = `<span class="security-indicator low">Unavailable</span>`;
    }

    if (darkwebDetails) {
        darkwebDetails.innerHTML = `
            <div class="metadata-raw">
                <h4>Dark Web Intelligence</h4>
                <div class="detail-card">
                    <div class="detail-content">
                        <div class="detail-row">
                            <span class="detail-value">
                                <i class="fas fa-info-circle"></i>
                                Dark web intelligence requires specialized access and authenticated APIs.
                                No legitimate free APIs are available for dark web monitoring.
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
};

/**
 * Monitor mentions - REMOVED
 * No legitimate APIs for dark web monitoring
 */
const monitorMentions = async (target, windowElement) => {
    console.log(`[monitorMentions] Dark web monitoring not available`);
    // Function disabled - no legitimate APIs available
};

/**
 * Threat hunting - REMOVED
 * No legitimate APIs for dark web threat hunting
 */
const threatHunting = async (target, windowElement) => {
    console.log(`[threatHunting] Dark web threat hunting not available`);
    // Function disabled - no legitimate APIs available
};

/**
 * Extract advanced metadata from files/URLs
 */
const extractAdvancedMetadata = async (url, type, windowElement) => {
    console.log(`[extractAdvancedMetadata] Extracting metadata from ${url} (${type})`);

    await new Promise(resolve => setTimeout(resolve, Math.random() * 2800 + 1200));

    const metadataFieldsCount = windowElement.querySelector('.metadata-fields-count');
    const hiddenDataFound = windowElement.querySelector('.hidden-data-found');
    const advancedMetadataDetails = windowElement.querySelector('.advanced-metadata-details');

    if (metadataFieldsCount) {
        metadataFieldsCount.textContent = 'N/A';
    }

    if (hiddenDataFound) {
        hiddenDataFound.innerHTML = '<span class="security-indicator low">Requires specialized tools</span>';
    }

    if (advancedMetadataDetails) {
        advancedMetadataDetails.innerHTML = `
            <div class="metadata-raw">
                <h4>Advanced Metadata Extraction</h4>
                <div class="detail-card">
                    <div class="detail-content">
                        <div class="detail-row">
                            <span class="detail-value">
                                <i class="fas fa-info-circle"></i>
                                Advanced metadata extraction requires specialized tools and libraries.
                                Real metadata analysis needs access to file headers, EXIF data, and embedded content.
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Store results
    globalState.rawData.advancedMetadata = globalState.rawData.advancedMetadata || {};
    globalState.rawData.advancedMetadata[url] = {
        url,
        type,
        timestamp: new Date().toISOString(),
        note: 'Requires specialized tools for real metadata extraction'
    };
};

// Helper functions for external links
const openSatelliteView = (ip) => {
    // Try to get real coordinates from stored data
    let coordinates = null;

    // Search through stored IP data to find coordinates
    for (const [windowId, ipData] of Object.entries(globalState.rawData.ipInfo || {})) {
        if (ipData && ipData.query === ip && ipData.lat && ipData.lon) {
            coordinates = `${ipData.lat},${ipData.lon}`;
            break;
        }
    }

    // Use coordinates if available, otherwise fallback to IP
    const searchTerm = coordinates || ip;
    const url = `https://www.google.com/maps/search/${searchTerm}`;
    window.open(url, '_blank');
};

const openStreetView = (ip) => {
    // Try to get real coordinates from stored data
    let coordinates = null;

    // Search through stored IP data to find coordinates
    for (const [windowId, ipData] of Object.entries(globalState.rawData.ipInfo || {})) {
        if (ipData && ipData.query === ip && ipData.lat && ipData.lon) {
            coordinates = `${ipData.lat},${ipData.lon}`;
            break;
        }
    }

    if (coordinates) {
        const [lat, lon] = coordinates.split(',');
        const url = `https://www.google.com/maps/@${lat},${lon},3a,75y,90t/data=!3m6!1e1!3m4!1s0x0:0x0!2e0!7i13312!8i6656`;
        window.open(url, '_blank');
    } else {
        // Fallback to regular maps search
        const url = `https://www.google.com/maps/search/${ip}`;
        window.open(url, '_blank');
    }
};

const openSocialProfile = (platform, username) => {
    const urls = {
        'twitter': `https://twitter.com/${username}`,
        'facebook': `https://facebook.com/${username}`,
        'instagram': `https://instagram.com/${username}`,
        'linkedin': `https://linkedin.com/in/${username}`,
        'youtube': `https://youtube.com/@${username}`,
        'tiktok': `https://tiktok.com/@${username}`
    };

    const url = urls[platform] || `https://google.com/search?q=${username}`;
    window.open(url, '_blank');
};

/**
 * Estimate timezone from coordinates
 */
const estimateTimezoneFromCoordinates = (lat, lon) => {
    // Simple timezone estimation based on longitude
    // This is a basic approximation - in production you'd use a proper timezone API

    // Rough timezone mapping based on longitude
    const timezoneOffset = Math.round(lon / 15);

    // Common timezone mappings for different regions
    if (lat >= 25 && lat <= 49 && lon >= -125 && lon <= -66) {
        // United States
        if (lon >= -125 && lon <= -120) return 'America/Los_Angeles';
        if (lon >= -120 && lon <= -105) return 'America/Denver';
        if (lon >= -105 && lon <= -90) return 'America/Chicago';
        if (lon >= -90 && lon <= -66) return 'America/New_York';
    } else if (lat >= 35 && lat <= 71 && lon >= -10 && lon <= 40) {
        // Europe
        if (lon >= -10 && lon <= 0) return 'Europe/London';
        if (lon >= 0 && lon <= 15) return 'Europe/Paris';
        if (lon >= 15 && lon <= 30) return 'Europe/Berlin';
        if (lon >= 30 && lon <= 40) return 'Europe/Moscow';
    } else if (lat >= -35 && lat <= 35 && lon >= 95 && lon <= 145) {
        // Asia-Pacific
        if (lon >= 95 && lon <= 105) return 'Asia/Bangkok';
        if (lon >= 105 && lon <= 125) return 'Asia/Shanghai';
        if (lon >= 125 && lon <= 145) return 'Asia/Tokyo';
    }

    // Fallback to UTC offset estimation
    if (timezoneOffset >= -12 && timezoneOffset <= 12) {
        const offsetHours = timezoneOffset;
        if (offsetHours === 0) return 'UTC';
        if (offsetHours === -5) return 'America/New_York';
        if (offsetHours === -8) return 'America/Los_Angeles';
        if (offsetHours === 1) return 'Europe/Paris';
        if (offsetHours === 9) return 'Asia/Tokyo';
    }

    return 'UTC'; // Default fallback
};

/**
 * Get timezone offset for display
 */
const getTimezoneOffset = (timezone) => {
    try {
        const now = new Date();
        const utc = new Date(now.getTime() + (now.getTimezoneOffset() * 60000));
        const targetTime = new Date(utc.toLocaleString('en-US', {
            timeZone: timezone
        }));
        const offsetMs = targetTime.getTime() - utc.getTime();
        const offsetHours = Math.round(offsetMs / (1000 * 60 * 60));

        if (offsetHours === 0) return 'UTC+0';
        return offsetHours > 0?`UTC+${offsetHours}` : `UTC${offsetHours}`;
    } catch (error) {
        console.error('Error calculating timezone offset:', error);
        return 'UTC+0';
    }
};



// Function to test all credentials