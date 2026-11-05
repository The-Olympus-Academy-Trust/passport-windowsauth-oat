var ldap = require('ldapjs');
var decodeSearchEntry = require('./decodeSearchEntry');


// Defaults so a misconfigured consumer can never hang forever - ldapjs treats
// 0/unset as "no limit", which previously left bind and search operations
// waiting indefinitely when AD was unreachable or slow.
var DEFAULT_TIMEOUT_MS = 5000;         // per-operation (bind/search)
var DEFAULT_CONNECT_TIMEOUT_MS = 5000; // TCP connect
var DEFAULT_IDLE_TIMEOUT_MS = 60000;   // reap idle connections

/**
 * Escapes a value for use in an LDAP filter (RFC 4515).
 *
 * NB: the previous implementation used HTML entities (&#40; / &#41;), which
 * LDAP filters do NOT decode - the nested-group lookup silently matched
 * nothing for DNs containing parentheses. Use LDAP backslash escapes instead.
 */
function escapeLdapFilterValue(value) {
    return value
        .replace(/\\/g, '\\5c')
        .replace(/\*/g, '\\2a')
        .replace(/\(/g, '\\28')
        .replace(/\)/g, '\\29')
        .replace(/\u0000/g, '\\00');
}

/**
 * Bind state machine:
 *
 *   'idle'      - not bound, no bind attempt in flight
 *   'binding'   - a bind attempt is in flight (new requests are queued)
 *   'connected' - bound and operational
 *
 * On bind failure the queue is flushed with the error (so pending requests
 * fail fast instead of hanging until the bind recovers) and the bind is
 * retried with backoff in the background. Previously a failed bind left the
 * queue wedged permanently, hanging every authentication until the process
 * restarted.
 */
var LdapLookup = module.exports = function(options){
    this._options = options;

    this._search_query = options.search_query ||
        '(&(objectclass=user)(|(sAMAccountName={0})(UserPrincipalName={0})))';

    this._bindState = 'idle';
    this._queue = [];
    this._bindAttempts = 0;

    this._client = options.client ? options.client : ldap.createClient({
        url:             options.url,
        maxConnections:  options.maxConnections || 10,
        bindDN:          options.bindDN,
        bindCredentials: options.bindCredentials,
        tlsOptions:      options.tlsOptions,
        reconnect:       options.reconnect,
        timeout:         options.timeout || DEFAULT_TIMEOUT_MS,
        connectTimeout:  options.connectTimeout || DEFAULT_CONNECT_TIMEOUT_MS,
        idleTimeout:     options.idleTimeout || DEFAULT_IDLE_TIMEOUT_MS
    });

    var self = this;

    // When the socket (re-)establishes, the connection is unbound - ldapjs
    // does not replay the bind automatically. Previously the client stayed
    // unbound after a reconnect and every search failed until the process
    // restarted.
    this._client.on('connect', function(){
        self._bind();
    });

    this._client.on('error', function(e){
        // Suppress logging of ECONNRESET if ldapjs's Client will automatically reconnect.
        if (e.errno === 'ECONNRESET' && self._client.reconnect) return;

        console.log('LDAP connection error:', e);
    });

    if (options.client) {
        this._bindState = 'connected';
        return;
    }

    this._bind();
};

// Kept as a derived property for backwards compatibility.
Object.defineProperty(LdapLookup.prototype, 'clientConnected', {
    get: function () {
        return this._bindState === 'connected';
    }
});

/**
 * Binds the client, guarding against concurrent attempts. Successful binds
 * execute queued searches; failed binds flush the queue with the error and
 * schedule a retry with exponential backoff (capped at 15s).
 */
LdapLookup.prototype._bind = function () {
    if (this._bindState === 'binding') {
        return; // an attempt is already in flight
    }

    this._bindState = 'binding';
    var self = this;

    this._client.bind(this._options.bindDN, this._options.bindCredentials, function(err) {
        if (err) {
            self._bindAttempts++;
            var delay = Math.min(500 * Math.pow(2, self._bindAttempts), 15000);
            console.log(
                'Error binding to LDAP (attempt ' + self._bindAttempts + '), retrying in ' + delay + 'ms',
                'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message
            );

            // Fail fast for anything queued rather than hanging until the
            // bind recovers.
            self._queue.forEach(function (item) {
                item.callback(err);
            });
            self._queue = [];
            self._bindState = 'idle';

            setTimeout(function () {
                self._bind();
            }, delay);
            return;
        }

        self._bindAttempts = 0;
        self._bindState = 'connected';

        var queue = self._queue;
        self._queue = [];
        queue.forEach(function (item) {
            item.exec();
        });
    });
};

/**
 * Flushes pending requests: after a successful bind they are executed
 * (re-issuing their searches over the now-working connection); after a bind
 * failure they receive the error so the caller can fail fast.
 */
LdapLookup.prototype._flushQueue = function (err) {
    var queue = this._queue;
    this._queue = [];

    queue.forEach(function (item) {
        if (err) {
            item.callback(err);
        } else {
            item.exec();
        }
    });
};

LdapLookup.prototype.search = function (username, callback) {
    var self = this;

    function exec(){
        var opts = {
            scope: 'sub',
            filter: self._search_query.replace(/\{0\}/ig, escapeLdapFilterValue(username))
        };

        // Guard so the callback is invoked exactly once even if the search
        // result stream emits both an error and an end event.
        var completed = false;
        function done(err, result) {
            if (completed) return;
            completed = true;
            callback(err, result);
        }

        self._client.search(self._options.base, opts, function(err, res){
            var entries = [];
            res.on('searchEntry', function(entry) {
                entries.push(entry);
            });

            res.on('error', function(err) {
                done(err);
            });

            res.on('end', function() {

                if (entries.length === 0) return done(null, null);

                var groupOpts = {
                    scope: 'sub',
                    filter: '(member:1.2.840.113556.1.4.1941:=' + escapeLdapFilterValue(entries[0].objectName) + ')'
                };

                var groupEntries = [];
                var groupCompleted = false;
                function groupDone(err) {
                    if (groupCompleted) return;
                    groupCompleted = true;

                    if (err) return done(err);

                    entries[0].attributes.find( function(element) {
                        if (element.type === "memberOf"){
                            element.vals = groupEntries;
                        }
                    });

                    done(null, decodeSearchEntry(entries[0]));
                }

                //Second call to LDAP, this time to query all groups user is part of, including nested groups.
                self._client.search(self._options.base, groupOpts, function(err, res){

                    res.on('searchEntry', function(entry) {
                        groupEntries.push( entry.objectName );
                    });

                    res.on('error', function(err) {
                        groupDone(err);
                    });

                    res.on('end', function() {
                        groupDone(null);
                    });

                });

            });

        });
    };


    if (this.clientConnected) {
        exec();
    } else {
        this._queue.push({ exec: exec, callback: callback });
    }
};
