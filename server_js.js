const http = require('http');
const fs = require('fs');

const PORT = process.env.PORT || 8080;

// Load RTSP URLs from file
function loadURLsFromFile(filename) {
    try {
        const data = fs.readFileSync(filename, 'utf8');
        return data.split('\n').filter(url => url.trim() !== '');
    } catch (err) {
        console.error('Error loading URLs:', err);
        return [];
    }
}

const urls = loadURLsFromFile('rtsp_url.txt');

const server = http.createServer((req, res) => {
    if (req.url === '/') {
        // Serve index.html
        fs.readFile(__dirname + '/index.html', (err, data) => {
            if (err) {
                res.writeHead(500);
                return res.end('Error loading index.html');
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (req.url === '/cameras') {
        // Return RTSP IP addresses as JSON
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(urls));
    } else if (req.url.startsWith('/play?url=')) {
        const rtspURL = decodeURIComponent(req.url.slice(10));
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
