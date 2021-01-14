module.exports = {
  mode: 'development',
  devtool: 'source-map',
  entry: {
    files: [
      '@babel/polyfill',
      './src/index.js'
    ]
  },
  output: {
    filename: 'owncloud.js',
    libraryTarget: 'umd'
  },
  module: {
    rules: [{
      test: /\.js?$/,
      exclude: /node_modules/,
      loader: 'babel-loader'
    }, {
      enforce: 'pre',
      test: /\.(js|vue)$/,
      exclude: /node_modules/,
      loader: 'eslint-loader'
    }]
  }
}
