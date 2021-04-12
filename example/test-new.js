
var IPTablesLogParser = require('../index');

// Create parser instance here.
var parser = new IPTablesLogParser();

// Add iptables log entry here.
var log=""
console.log(parser.ParseIPTablesLog(log));
