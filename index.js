'use strict';

let crypto;

// Node can be compiled without the crypto module, so check for it:
try {
    crypto = require('node:crypto');
} catch (err) {
    console.error('crypto support is disabled!');
}

const net = require('node:net');
const util = require('node:util');

const icmp = require('./icmp');
const icmp6 = require('./icmp6');

/**
 * This function calculates the Community ID string for the given flow tuple and
 * configuration. For example:
 *
 *    communityid.calc('tcp', '128.232.110.120', '66.35.250.204', 34855, 80)
 *
 * yields '1:LQU9qZlK+B5F3KDmev6m5PMibrg='.
 *
 * You'll usually specify a full flow 5-tuple including the IP protocol, source
 * and destination IP address, as well as source and destination ports.  The
 * protocol can be a string like "tcp" or "TCP", or the protocol's 8-byte
 * numeric identifier as per the IANA registry (for example 6 to mean TCP). The
 * IP addresses are always string, the ports always integers in the [0, 65535]
 * range. For convenience the ports may also be strings (e.g. '80' instead of
 * 80).
 *
 * When specifying a full tuple, the protocol must be one of TCP, UDP, ICMP,
 * ICMPv6, or SCTP. Per the Community ID spec, you may omit the ports to produce
 * a hash of the IP address pair plus protocol number.
 *
 * To establish separate hashing "domains" (i.e., to avoid colliding hashes on
 * identical input values), you can optionally provide an integer seed value in
 * the [0, 65535] range.
 *
 * In some use cases it can be handy to disable the base64-encoding of the SHA1
 * hash result. Set the use_base64 argument to false to disable it.
 *
 * In case of any problems with the input arguments, the function reports an
 * error message via communityid.error() (which defaults to writing to
 * console.error()), and returns null. Otherwise, the function returns a
 * Community ID string value.
 *
 * For troubleshooting or to guide alternative implementations, the function
 * will log details about the hashed values to stderr if Node is invoked with
 * NODE_DEBUG=communityid (or "communityid" being in a comma-separated list of
 * debug streams).
 *
 * @param {(string|number)} proto - The flow's transport protocol.
 * @param {string} saddr - The flow's source IP address (IPv4 or IPv6).
 * @param {string} daddr - The flow's destination IP address (IPv4 or IPv6).
 * @param {(string|number)} [sport] - The flow's source port, or the ICMP type for ICMP/ICMPv6.
 * @param {(string|number)} [dport] - The flow's destination port, or the ICMP code for ICMP/ICMPv6.
 * @param {number} [seed] - An integer in [0, 65535] to seed the hash input. Optional, defaults to 0.
 * @param {bool} [use_base64] - Whether to base64-encode the SHA1 hash. Optional, defaults to true.
 */
exports.calc = function(proto, saddr, daddr, sport=null, dport=null, seed=0, use_base64=true) {

    const PROTO_ICMP = 1;
    const PROTO_TCP = 6;
    const PROTO_UDP = 17;
    const PROTO_ICMP6 = 58;
    const PROTO_SCTP = 132;

    const proto_map = new Map(Object.entries({
        "icmp": PROTO_ICMP,
        "tcp": PROTO_TCP,
        "udp": PROTO_UDP,
        "icmp6": PROTO_ICMP6,
        "sctp": PROTO_SCTP,
    }));

    const debuglog = util.debuglog('communityid');
    const have_sport = sport !== null && sport !== undefined;
    const have_dport = dport !== null && dport !== undefined;
    const have_ports = have_sport && have_dport;

    // Based on https://github.com/locutusjs/locutus/blob/master/src/php/network/inet_pton.js
    //
    // Copyright (c) 2007-2016 Kevin van Zonneveld (https://kvz.io)
    // and Contributors (https://locutus.io/authors)
    //
    // Permission is hereby granted, free of charge, to any person obtaining a copy of
    // this software and associated documentation files (the "Software"), to deal in
    // the Software without restriction, including without limitation the rights to
    // use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    // of the Software, and to permit persons to whom the Software is furnished to do
    // so, subject to the following conditions:
    //
    // The above copyright notice and this permission notice shall be included in all
    // copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    // SOFTWARE.
    function inet_pton(val) {
        let m, i, j;
        const f = String.fromCharCode;

        // IPv4 (assuming dotted-quad, not exotic numeral forms)
        m = val.match(/^(?:\d{1,3}(?:\.|$)){4}/);
        if (m) {
            m = m[0].split('.');
            m = f(m[0], m[1], m[2], m[3]);
            // Return if 4 bytes, otherwise false.
            return m.length === 4 ? m : false;
        }

        // IPv6
        if (val.length > 39)
            return false;

        m = val.split('::');
        // :: can't be used more than once in IPv6.
        if (m.length > 2)
            return false;

        const reHexDigits = /^[\da-f]{1,4}$/i;

        for (let j = 0; j < m.length; j++) {
            if (m[j].length === 0) // Skip if empty.
                continue;
            m[j] = m[j].split(':');
            for (let i = 0; i < m[j].length; i++) {
                let hextet = m[j][i];
                // check if valid hex string up to 4 chars
                if (!reHexDigits.test(hextet)) {
                    return false;
                }

                hextet = parseInt(hextet, 16);

                // Would be NaN if it was blank, return false.
                if (isNaN(hextet))
                    // Invalid IP.
                    return false;
                m[j][i] = f(hextet >> 8, hextet & 0xFF);
            }
            m[j] = m[j].join('');
        }

        return m.join('\x00'.repeat(16 - m.reduce((tl, m) => tl + m.length, 0)))
    }

    function htons(val) {
        return String.fromCharCode((val & 0x0000FF00) >>> 8) +
            String.fromCharCode((val & 0x000000FF) >>> 0);
    }

    function strToInt(val, msg) {
        if (typeof val !== 'string')
            return val;

        val = parseInt(val);

        if (isNaN(val)) {
            exports.error(msg);
            return null;
        }

        return val;
    }

    function order_tuple(saddr, daddr, sport, dport) {
        if (saddr < daddr)
            return [saddr, daddr, sport, dport];
        if (saddr == daddr && have_ports && sport < dport)
            return [saddr, daddr, sport, dport];
        return [daddr, saddr, dport, sport];
    }

    // If the initial crypto module load failed, do nothing.
    if (crypto == null)
        return null;

    // Validate input values.

    // The protocol may be a name like 'tcp', a string containing a number
    // ('6'), or a number. Convert to number if necessary. Range checking of the
    // number continues below.
    if (typeof proto == 'string') {
        if (proto_map.has(proto.toLowerCase())) {
            proto = proto_map.get(proto.toLowerCase());
        } else {
            proto = strToInt(proto, `invalid protocol "${proto}"`);
            if (proto === null)
                return null;
        }
    }

    // The protocol number must be an 8-byte integer.
    if (! Number.isInteger(proto) || proto < 0 || proto > 255) {
        exports.error(`invalid protocol "${proto}"`);
        return null;
    }

    // We need either two ports or none:
    if (have_sport != have_dport) {
        exports.error(`invalid port mix "${sport}"/"${dport}"`);
        return null;
    }

    if (have_ports) {
        sport = strToInt(sport, `invalid source port "${sport}"`);
        if (sport === null)
            return null;

        dport = strToInt(dport, `invalid dest port "${dport}"`);
        if (dport === null)
            return null;

        if (typeof sport != 'number' || ! Number.isInteger(sport)
            || sport < 0 || sport > 65535) {
            exports.error(`invalid source port "${sport}"`);
            return null;
        }
        if (typeof dport != 'number' || ! Number.isInteger(dport)
            || dport < 0 || dport > 65535) {
            exports.error(`invalid dest port "${dport}"`);
            return null;
        }

        // If we have ports, the protocol must be one of the protocols
        // for which we support the port notion. Otherwise we cannot
        // know whether flipping endpoints is semantically valid.
        if (! Array.from(proto_map.values()).includes(proto)) {
            exports.error(`invalid protocol "${proto}" for using ports`);
            return null;
        }
    }

    // The addresses must be valid IPv4/IPv6 strings.
    if (! net.isIP(saddr)) {
        exports.error(`invalid source IP address "${saddr}"`);
        return null;
    }

    if (! net.isIP(daddr)) {
        exports.error(`invalid dest IP address "${daddr}"`);
        return null;
    }

    // The seed must be a 16-bit integer.
    if (typeof seed != 'number' || ! Number.isInteger(seed)
        || seed < 0 || seed > 65535) {
        exports.error(`invalid seed value "${seed}"`);
        return null;
    }

    let is_one_way = false;

    if (have_ports) {
        // Adjust "ports" in ICMP scenarios
        if (proto == PROTO_ICMP) {
            [sport, dport, is_one_way] = icmp.get_port_equivalents(sport, dport);
        } else if (proto == PROTO_ICMP6) {
            [sport, dport, is_one_way] = icmp6.get_port_equivalents(sport, dport);
        }

        // Convert flow tuple parts to network byte order strings ...
        sport = htons(sport);
        dport = htons(dport);
    }

    // ... and do so for remainder of the flow tuple.
    saddr = inet_pton(saddr);
    daddr = inet_pton(daddr);
        proto = String.fromCharCode(proto);

    // Flip endpoints if needed:
    if (! is_one_way)
        [saddr, daddr, sport, dport] = order_tuple(saddr, daddr, sport, dport);

    let shasum = crypto.createHash('sha1');

    // Helper to dump the produced buffer content, for troubleshooting
    // Run with NODE_DEBUG=communityid environment to generate output.
    function hash_update(data, context) {
        if (debuglog.enabled) {
            let buf = [];
            for (let i = 0; i < data.length; i++) {
                let hex = data.charCodeAt(i).toString(16);
                buf.push(('0' + hex).slice(-2));
            }
            debuglog(`${context.padStart(7, ' ')} ${buf.join(':')}`);
        }
        shasum.update(data, 'binary');
    }

    hash_update(htons(seed), 'seed');
    hash_update(saddr, 'saddr');
    hash_update(daddr, 'daddr');
    hash_update(proto, 'proto');
    hash_update('\x00', 'padding');

    // The C, Python, and JavaScript implementations currently allow skipping
    // ports but (per the spec) require a protocol. It's not clear whether that
    // information is available in all use cases -- something to revisit in v2.
    if (have_ports) {
        hash_update(sport, 'sport');
        hash_update(dport, 'dport');
    }

    if (! use_base64)
        return "1:" + shasum.digest('hex');

    return  "1:" + shasum.digest().toString('base64');
}

/**
 * The calc() function invokes this method with an error message whenever a
 * fatal problem comes up that prevents the calculation. By default it
 * dispatches to console.error(). The calculation will subsequently abort and
 * return null.
 *
 * @param {string} - An error message.
 */
exports.error = function(msg) {
    console.error(msg);
}
