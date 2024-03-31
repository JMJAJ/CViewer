const fs = require('fs');
const { loadURLsFromFile, saveURLsToFile } = require('./fileHandler');

let urls = loadURLsFromFile('rtsp_url.txt');

function handleRequest(req, res) {
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
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Playing RTSP stream from ${rtspURL}`);
    } else if (req.url === '/add-ip' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString(); // convert Buffer to string
        });
        req.on('end', () => {
            const newIp = body.trim();
            if (newIp) {
                urls.push(newIp);
                saveURLsToFile('rtsp_url.txt', urls);
                res.writeHead(200);
                res.end();
            } else {
                res.writeHead(400);
                res.end('Empty IP');
            }
        });
    } else {
        res.writeHead(404);
        res.end('Not Found');
    }
}

module.exports = { handleRequest };
