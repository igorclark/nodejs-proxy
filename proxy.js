/*
** Peteris Krumins (peter@catonmat.net)
** http://www.catonmat.net	--	good coders code, great reuse
**
** A simple proxy server written in node.js.
**
*/

var http	= require('http');
var sys		= require('sys');

sys.log_error = function(error_msg) {
	this.log("\033[0;31mERROR: " + error_msg + "\033[m");
};

sys.log_info = function(info_msg) {
	this.log("\033[0;33mINFO: " + info_msg + "\033[m");
};

var fs		= require('fs');
var config	= require('./config').config;

var blacklist	= [];
var iplist		= [];

var fs_update_interval		= 60 * 1000;	// 60 seconds

var url_truncate_length		= 50;
var host_truncate_length	= 20;
var ellipsis				= "[...]";

fs.watchFile(
	config.black_list,
	{
		persistent: true,
		interval: fs_update_interval
	},
	function(c,p) {
		update_blacklist();
	}
);

fs.watchFile(
	config.allow_ip_list,
	{
		persistent: true,
		interval: fs_update_interval
	},
	function(c,p) {
		update_iplist();
	}
);

function update_list(msg, file, mapf, collectorf) {
	fs.stat(file, function(err, stats) {
		if (!err) {
			sys.log_info(msg);
			collectorf(fs.readFileSync(file, 'utf-8')
										.split('\n')
										.filter(function(rx) { return rx.length })
										.map(mapf));
		}
		else {
			sys.log_error("File '" + file + "' was not found.");
			collectorf([]);
		}
	});
}

function update_blacklist() {
	update_list(
		"Updating host black list.",
		config.black_list,
		function(rx) { return RegExp(rx) },
		function(list) { blacklist	= list }
	);
}

function update_iplist() {
	update_list(
		"Updating allowed ip list.",
		config.allow_ip_list,
		function(ip){return ip},
		function(list) { iplist	= list }
	);
}

function get_padding_spaces(pad_length) {
	var pad	= "";
	for(var i=0;i<pad_length;i++) {
		pad += ' ';
	}
	return pad;
}

function fixed_length_string(str_to_fix, pad_length) {
	if(str_to_fix.length === (pad_length + ellipsis.length)) {
		return str_to_fix;
	}
	else if(str_to_fix.length > pad_length) {
		return str_to_fix.substring(0, pad_length) + ellipsis;
	}
	else {
		return str_to_fix + get_padding_spaces(pad_length + ellipsis.length - str_to_fix.length);
	}
}

function ip_allowed(ip) {
	return	iplist.some(function(ip_)		{ return ip==ip_; });
}

function host_allowed(host) {
	return	!blacklist.some(function(host_)	{ return host_.test(host); });
}

function deny(response, msg) {
	response.writeHead(401);
	response.write(msg);
	response.end();
}

function server_cb(request, response) {
	var ip	= request.connection.remoteAddress;
	if (!ip_allowed(ip)) {
		msg	= "IP " + ip + " is not allowed to use this proxy";
		deny(response, msg);
		sys.log_error(msg);
		return;
	}

	if (!host_allowed(request.url)) {
		msg	= "Host " + request.url + " has been denied by proxy configuration";
		deny(response, msg);
		sys.log_error(msg);
		return;
	}

	// parse out host, port, URL from request
	var req_data	= request.url.match(/^(?:f|ht)tp(?:s)?\:\/\/([^/:]+)(:[0-9]+)?(.*)/im);
	var req_host	= req_data[1].toString();
	var req_port	= req_data[2] ? req_data[2].toString() : 80;
	var req_url		= req_data[3].toString();

	if(!request.headers.host) { request.headers['host']	= req_host; }

	sys.log(
		request.method
		+ " | " + fixed_length_string(req_url, url_truncate_length)
		+ " | " + fixed_length_string(req_host, host_truncate_length)
		+ " | " + req_port
		+ " | " + ip
	);

	var proxy	= http.createClient(req_port, req_host);

	// add error handler to deal with network timeouts/disconnects/etc
	proxy.on('error', function(err) {
		sys.log_error(err.toString() + " on request to " + req_host + ":" + req_port);
	});

	var proxy_request	= proxy.request(request.method, req_url, request.headers);

	proxy_request.addListener('response', function(proxy_response) {
		proxy_response.addListener('data', function(chunk) {
				response.write(chunk, 'binary');
			}
		);
		proxy_response.addListener('end', function() {
				response.end();
			}
		);
		response.writeHead(proxy_response.statusCode, proxy_response.headers);
	});

	request.addListener('data', function(chunk) {
			proxy_request.write(chunk, 'binary');
		}
	);

	request.addListener('end', function() {
			proxy_request.end();
		}
	);
}

update_blacklist();
update_iplist();

sys.log("Starting the proxy server on port '" + config.proxy_port);
http.createServer(server_cb).listen(config.proxy_port);
