const express = require('express');
const fs = require('fs');

const PORT = process.env.PORT || 8080;
const app = express();

// Load RTSP URLs from JSON file
function loadURLsFromJSON(filename) {
    try {
        const data = fs.readFileSync(filename, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Error loading URLs:', err);
        return [];
    }
}

const urls = loadURLsFromJSON('db.json');

// Serve index.html when root URL is requested
app.get('/', (req, res) => {
    fs.readFile(__dirname + '/index.html', (err, data) => {
        if (err) {
            res.status(500).send('Error loading index.html');
            return;
        }
        res.status(200).type('text/html').send(data);
    });
});

// Serve RTSP URLs as JSON when /cameras endpoint is requested
app.get('/cameras', (req, res) => {
    res.status(200).json(urls);
});

// Handle other requests with a 404 response
app.use((req, res) => {
    res.status(404).send('Not Found');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
