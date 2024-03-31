const fs = require('fs');

function loadURLsFromFile(filename) {
    try {
        const data = fs.readFileSync(filename, 'utf8');
        return data.split('\n').filter(url => url.trim() !== '');
    } catch (err) {
        console.error('Error loading URLs:', err);
        return [];
    }
}

function saveURLsToFile(filename, urls) {
    fs.writeFile(filename, urls.join('\n'), { mode: 0o666 }, err => {
        if (err) {
            console.error('Error saving URLs:', err);
        } else {
            console.log('URLs saved to file');
        }
    });
}

module.exports = { loadURLsFromFile, saveURLsToFile };
