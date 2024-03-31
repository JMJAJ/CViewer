const express = require('express');
const fs = require('fs');

const app = express();
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

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.get('/cameras', (req, res) => {
    // Return RTSP IP addresses as JSON
    res.json(urls);
});

app.get('/play', (req, res) => {
    const rtspURL = req.query.url;
    console.log(`Playing RTSP stream from ${rtspURL}`);
    // Implement RTSP stream playing logic here
    // For demonstration, we just print the URL
    res.send(`Playing RTSP stream from ${rtspURL}`);
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
