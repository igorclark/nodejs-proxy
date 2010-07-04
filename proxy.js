/*
** Peteris Krumins (peter@catonmat.net)
** http://www.catonmat.net  --  good coders code, great reuse
**
** A simple proxy server written in node.js.
**
*/

var http = require('http');
var sys  = require('sys');
var fs   = require('fs');

var config = require('./config').config;

var blacklist = [];
var iplist    = [];

fs.watchFile(config.black_list,    function(c,p) { update_blacklist(); });
fs.watchFile(config.allow_ip_list, function(c,p) { update_iplist(); });

function update_list(msg, file, mapf, collectorf) {
  fs.stat(file, function(err, stats) {
    if (!err) {
      sys.log(msg);
      collectorf(fs.readFileSync(file, 'utf-8')
                   .split('\n')
                   .filter(function(rx) { return rx.length })
                   .map(mapf));
    }
    else {
      sys.log("File '" + file + "' was not found.");
      collectorf([]);
    }
  });
}

function update_blacklist() {
  update_list(
    "Updating host black list.",
    config.black_list,
    function(rx) { return RegExp(rx) },
    function(list) { blacklist = list }
  );
}

function update_iplist() {
  update_list(
    "Updating allowed ip list.",
    config.allow_ip_list,
    function(ip){return ip},
    function(list) { iplist = list }
  );
}

function ip_allowed(ip) {
  return iplist.some(function(ip_) { return ip==ip_; });
}

function host_allowed(host) {
  return !blacklist.some(function(host_) { return host_.test(host); });
}

function deny(response, msg) {
  response.writeHead(401);
  response.write(msg);
  response.end();
}

function server_cb(request, response) {
  var ip = request.connection.remoteAddress;
  if (!ip_allowed(ip)) {
    msg = "IP " + ip + " is not allowed to use this proxy";
    deny(response, msg);
    sys.log(msg);
    return;
  }

  if (!host_allowed(request.url)) {
    msg = "Host " + request.url + " has been denied by proxy configuration";
    deny(response, msg);
    sys.log(msg);
    return;
  }

  // parse out host, port, URL from request
  var req_data  = request.url.match(/^(?:f|ht)tp(?:s)?\:\/\/([^/:]+)(:[0-9]+)?(.*)/im);
  var req_host  = req_data[1].toString();
  var req_port  = req_data[2] ? req_data[2].toString() : 80;
  var req_url   = req_data[3].toString();

  if(!request.headers.host) { request.headers['host'] = req_host; }

  sys.log("Getting " + req_url + " from " + req_host + " on port " + req_port + " for client " + ip);

  var proxy = http.createClient(req_port, req_host);
  var proxy_request = proxy.request(request.method, req_url, request.headers);

  proxy_request.addListener('response', function(proxy_response) {
    proxy_response.addListener('data', function(chunk) {
      response.write(chunk, 'binary');
    });
    proxy_response.addListener('end', function() {
      response.end();
    });
    response.writeHead(proxy_response.statusCode, proxy_response.headers);
  });
  request.addListener('data', function(chunk) {
    proxy_request.write(chunk, 'binary');
  });
  request.addListener('end', function() {
    proxy_request.end();
  });
}

update_blacklist();
update_iplist();

sys.log("Starting the proxy server on port '" + config.proxy_port);
http.createServer(server_cb).listen(config.proxy_port);

