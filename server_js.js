const http = require('http');
const fs = require('fs');

const PORT = process.env.PORT || 8080;

// Load IP addresses from JSON file
function loadIPAddressesFromFile(filename) {
    try {
        const data = fs.readFileSync(filename, 'utf8');
        const jsonData = JSON.parse(data);
        return jsonData.IPAddresses;
    } catch (err) {
        console.error('Error loading IP addresses:', err);
        return [];
    }
}

const urls = loadIPAddressesFromFile('urls.json');

const server = http.createServer((req, res) => {
    if (req.url === '/') {
        fs.readFile(__dirname + '/index.html', (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end('Error loading index.html');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (req.url === '/cameras') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(urls));
    } else if (req.url.startsWith('/play')) {
        const rtspURL = req.url.split('=')[1];
        console.log(`Playing RTSP stream from ${rtspURL}`);
        // Implement RTSP stream playing logic here
        // For demonstration, we just print the URL
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Playing RTSP stream from ${rtspURL}`);
    } else {
        res.writeHead(404);
        res.end('Not Found');
    }
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
