const { exec } = require('child_process');
module.exports = function greet(name) {
  exec('echo ' + name);
  return 'Hello ' + name;
};
