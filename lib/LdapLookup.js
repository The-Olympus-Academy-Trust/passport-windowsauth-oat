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

                callback(null, decodeSearchEntry(entries[0]));

            });

            // res.on('end', function() {
            //     if(entries.length === 0) return callback(null, null);

            //     var totalEntry = entries[0].object;

            //     if ( totalEntry.hasOwnProperty( 'objectGUID' ) ) {
            //         totalEntry.objectGUID = formatGUID( totalEntry.objectGUID );
            //     }

            //     var groupOpts = {
            //         scope: 'sub',
            //         filter: '(member:1.2.840.113556.1.4.1941:=' + entries[0].objectName + ')'
            //     };

            //     var groupEntries = [];

            //     //Second call to LDAP, this time to query all groups user is part of, including nested groups.
            //     self._client.search(self._options.base, groupOpts, function(err, res){

            //         res.on('searchEntry', function(entry) {
            //             groupEntries.push(entry.objectName);
            //         });

            //         res.on('error', function(err) {
            //             callback(err);
            //         });

            //         res.on('end', function() {

            //             totalEntry['memberOf'] = groupEntries;

            //             callback(null, totalEntry);
            //         });

            //     });
            // });
        });
    }

    if(this.clientConnected){
        exec();
    } else {
        this._queue.push(exec);
    }
};


// function formatGUID( objectGUID ) {

//     var data = new Buffer( objectGUID, 'binary' );

//     //If the byte length of the objectGUID is less than 16 we append a = character on the end
//     if( Buffer.byteLength(data) < 16 ){
//         var addBuffer = new Buffer("=", 'binary');
//         data = Buffer.concat([data,addBuffer]);
//     }


//     // GUID_FORMAT_D
//     var template = '{3}{2}{1}{0}-{5}{4}-{7}{6}-{8}{9}-{10}{11}{12}{13}{14}{15}';

//     // check each byte
//     for ( var i = 0; i < data.length; i++ ) {

//         // get the current character from that byte
//         var dataStr = data[ i ].toString( 16 );

//         dataStr = data[ i ] >= 16 ? dataStr : '0' + dataStr;

//         // insert that character into the template
//         template = template.replace( new RegExp( '\\{' + i + '\\}', 'g' ), dataStr );

//     }

//     return template;

// }