const http = require('http');
const fs = require('fs');

const PORT = process.env.PORT || 8080;

// Function to load RTSP URLs from file
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
        // Serve index.html when root URL is requested
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
        // Serve RTSP URLs as JSON when /cameras endpoint is requested
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(urls));
    } else {
        // Handle other requests with a 404 response
        res.writeHead(404);
        res.end('Not Found');
    }
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
