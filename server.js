const express = require('express');
const request = require('request');
const jwt = require('jsonwebtoken');

// Create an Express app
const app = express();

// Middleware to verify the OAuth access token and extract the user ID
app.use((req, res, next) => {
  const accessToken = req.headers.authorization?.split(' ')[1];

  if (!accessToken) {
    res.status(401).send('Unauthorized\n no token\n');
    return;
  }

  // Verify the access token and extract the user ID from the JWT payload
  jwt.verify(accessToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      res.status(401).send('Unauthorized');
      return;
    }

    req.userId = decoded.sub;
    next();
  });
});

// Route to check if the user has cluster admin rights
app.get('/', (req, res) => {
  // Make a request to the OpenShift API server to check the user's roles
  request({
    url: `https://${process.env.OPENSHIFT_API_HOST}/apis/user.openshift.io/v1/users/${req.userId}`,
    headers: {
      authorization: req.headers.authorization
    },
    json: true
  }, (err, response, body) => {
    if (err || response.statusCode !== 200) {
      res.status(500).send('Error');
      return;
    }

    // Check if the user has the "cluster-admin" role
    const clusterAdminRole = body.metadata.annotations['user.openshift.io/cluster-admin'];

    if (clusterAdminRole !== 'true') {
      res.send('You do not have cluster admin rights');
      return;
    }

    res.send('You have cluster admin rights');
  });
});

// Start the server
app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
