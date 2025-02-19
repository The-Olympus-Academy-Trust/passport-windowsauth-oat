var ldap = require('ldapjs');
var decodeSearchEntry = require('./decodeSearchEntry');


var LdapLookup = module.exports = function(options){
    this._options = options;

    this._search_query = options.search_query ||
        '(&(objectclass=user)(|(sAMAccountName={0})(UserPrincipalName={0})))';

    this._client = options.client ? options.client : ldap.createClient({
        url:             options.url,
        maxConnections:  options.maxConnections || 10,
        bindDN:          options.bindDN,
        bindCredentials: options.bindCredentials,
        tlsOptions:      options.tlsOptions,
        reconnect:       options.reconnect,
        timeout:         options.timeout,
        connectTimeout:  options.connectTimeout,
        idleTimeout:     options.idleTimeout
    });

    this._client.on('error', function(e){
        // Suppress logging of ECONNRESET if ldapjs's Client will automatically reconnect.
        if (e.errno === 'ECONNRESET' && self._client.reconnect) return;
    
        console.log('LDAP connection error:', e);
    });

    if (options.client) {
        this.clientConnected = true;
        return;
    }

    this._queue = [];
    var self = this;
    this._client.bind(options.bindDN, options.bindCredentials, function(err) {
        if(err){
            return console.log("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
        }
        self.clientConnected = true;
        self._queue.forEach(function (cb) { cb(); });
    });
};




LdapLookup.prototype.search = function (username, callback) {
    var self = this;
    function exec(){
        
        var opts = {
            scope: 'sub',
            filter: self._search_query.replace(/\{0\}/ig, username)
        };

        self._client.search(self._options.base, opts, function(err, res){
            var entries = [];
            res.on('searchEntry', function(entry) {
                entries.push(entry);
            });

            res.on('error', function(err) {
                callback(err);
            });

            res.on('end', function() {

                if(entries.length === 0) return callback(null, null);

                const userName = entries[0].objectName.split('').map(char => {
                    if(char === '(') { 
                        return '&#40;';
                      } else if(char === ')') {
                          return '&#41;';
                      } else {
                          return char;
                      }
                }).join('');

                var groupOpts = {
                    scope: 'sub',
                    filter: '(member:1.2.840.113556.1.4.1941:=' + userName + ')'
                };

                var groupEntries = [];

                //Second call to LDAP, this time to query all groups user is part of, including nested groups.
                self._client.search(self._options.base, groupOpts, function(err, res){

                    res.on('searchEntry', function(entry) {
                        groupEntries.push( entry.objectName );
                    });

                    res.on('error', function(err) {
                        callback(err);
                    });

                    res.on('end', function() {

                        entries[0].attributes.find( (element) => {
                            if (element.type === "memberOf"){
                                element.vals = groupEntries;
                            }
                        });

                        callback(null, decodeSearchEntry(entries[0]));
                    });

                });

            });

        });
    };


    if(this.clientConnected){
        exec();
    } else {
        this._queue.push(exec);
    }
};