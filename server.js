const http = require('http');
const { handleRequest } = require('./serverHandler');

const PORT = process.env.PORT || 8080;

const server = http.createServer(handleRequest);

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
