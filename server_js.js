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

let urls = loadURLsFromFile('rtsp_url.txt');

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
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

function saveURLsToFile(filename, urls) {
    fs.writeFile(filename, urls.join('\n'), { mode: 0o666 }, err => {
        if (err) {
            console.error('Error saving URLs:', err);
        } else {
            console.log('URLs saved to file');
        }
    });
}
