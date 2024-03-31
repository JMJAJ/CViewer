const express = require('express');
const fs = require('fs');
const app = express();

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

// Middleware to set CSP headers allowing HTTP requests
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', 'upgrade-insecure-requests');
    next();
});

app.get('/', (req, res) => {
    fs.readFile(__dirname + '/index.html', (err, data) => {
        if (err) {
            res.writeHead(500);
            res.end('Error loading index.html');
            return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data);
    });
});

app.get('/cameras', (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(urls));
});

app.get('/play', (req, res) => {
    const rtspURL = req.query.url;
    console.log(`Playing RTSP stream from ${rtspURL}`);
    // Implement RTSP stream playing logic here
    // For demonstration, we just print the URL
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`Playing RTSP stream from ${rtspURL}`);
});

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
