const path = require('path');

module.exports = {
    entry: './hash_password.js',
    output: {
        filename: 'bundle.js',
        path: path.resolve(__dirname, 'dist'),
    },
    resolve: {
        fallback: {
            crypto: require.resolve('crypto-browserify'),
        },
    },
};
