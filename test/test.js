'use strict';

const { mock, test } = require('node:test');
const assert = require('node:assert').strict;

const communityid = require('..');

function assertEqualID(tuple, correct_results) {
    let i = 0;

    for (let config_args of [[0, true], [0, false], [1, true]]) {
        let res = communityid.calc(
            tuple['proto'], tuple['saddr'], tuple['daddr'],
            tuple['sport'], tuple['dport'],
            config_args[0], config_args[1]);

        assert.equal(res, correct_results[i++]);
    }
}

function assertNullIDWithError(tuple, pattern, seed=0) {
    let msg = '';

    communityid.error = mock.fn((a_msg) => {
        msg = a_msg;
    });

    let res = communityid.calc(
        tuple['proto'], tuple['saddr'], tuple['daddr'],
        tuple['sport'], tuple['dport'], seed);

    assert.equal(res, null);
    assert.equal(communityid.error.mock.callCount(), 1);
    assert.match(msg, pattern);

    mock.reset();
}

test('icmp 1', (t) => {
    assertEqualID(
        {'proto': 'icmp',
         'saddr': '192.168.0.89',
         'daddr': '192.168.0.1',
         'sport': 8,
         'dport': 0},
        ['1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
         '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
         '1:03g6IloqVBdcZlPyX8r0hgoE7kA=']);
})

test('icmp 2', (t) => {
    assertEqualID(
        {'proto': 'icmp',
         'daddr': '192.168.0.89',
         'saddr': '192.168.0.1',
         'dport': 8,
         'sport': 0},
        ['1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
         '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
         '1:03g6IloqVBdcZlPyX8r0hgoE7kA=']);
})

// This is correct: message type 20 (experimental) isn't
// one we consider directional, so the message code ends up
// in the hash computation, and thus two different IDs result:
test('icmp 3', (t) => {
    assertEqualID(
        {'proto': 'icmp',
         'saddr': '192.168.0.89',
         'daddr': '192.168.0.1',
         'sport': 20,
         'dport': 0},
        ['1:3o2RFccXzUgjl7zDpqmY7yJi8rI=',
         '1:de8d9115c717cd482397bcc3a6a998ef2262f2b2',
         '1:lCXHHxavE1Vq3oX9NH5ladQg02o=']);
})

// Therefore the following does _not_ get treated as the
// reverse direction, but _does_ get treated the same as
// the first two tuples, because for message type 0 the
// code is currently ignored.
test('icmp 4', (t) => {
    assertEqualID(
        {'proto': 'icmp',
         'saddr': '192.168.0.1',
         'daddr': '192.168.0.89',
         'sport': 0,
         'dport': 20},
        ['1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
         '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
         '1:03g6IloqVBdcZlPyX8r0hgoE7kA=']);
})

test('icmp 5', (t) => {
    assertEqualID(
        {'proto': 'icmp',
         'saddr': '192.168.0.89',
         'daddr': '192.168.0.1',
         'sport': 20,
         'dport': 1},
        ['1:tz/fHIDUHs19NkixVVoOZywde+I=',
         '1:b73fdf1c80d41ecd7d3648b1555a0e672c1d7be2',
         '1:Ie3wmFyxiEyikbsbcO03d2nh+PM=']);
})

test('icmp 6', (t) => {
    assertEqualID(
        {'proto': 1,
         'saddr': '192.168.0.89',
         'daddr': '192.168.0.1',
         'sport': 20,
         'dport': 1},
        ['1:tz/fHIDUHs19NkixVVoOZywde+I=',
         '1:b73fdf1c80d41ecd7d3648b1555a0e672c1d7be2',
         '1:Ie3wmFyxiEyikbsbcO03d2nh+PM=']);
})

test('icmp6 1', (t) => {
    assertEqualID(
        {'proto': 'icmp6',
         'saddr': 'fe80::200:86ff:fe05:80da',
         'daddr': 'fe80::260:97ff:fe07:69ea',
         'sport': 135,
         'dport': 0},
        ['1:dGHyGvjMfljg6Bppwm3bg0LO8TY=',
         '1:7461f21af8cc7e58e0e81a69c26ddb8342cef136',
         '1:kHa1FhMYIT6Ym2Vm2AOtoOARDzY=']);
})

test('icmp6 2', (t) => {
    assertEqualID(
        {'proto': 'icmp6',
         'saddr': 'fe80::260:97ff:fe07:69ea',
         'daddr': 'fe80::200:86ff:fe05:80da',
         'sport': 136,
         'dport': 0},
        ['1:dGHyGvjMfljg6Bppwm3bg0LO8TY=',
         '1:7461f21af8cc7e58e0e81a69c26ddb8342cef136',
         '1:kHa1FhMYIT6Ym2Vm2AOtoOARDzY=']);
})


test('icmp6 3', (t) => {
    assertEqualID(
        {'proto': 'icmp6',
         'saddr': '3ffe:507:0:1:260:97ff:fe07:69ea',
         'daddr': '3ffe:507:0:1:200:86ff:fe05:80da',
         'sport': 3,
         'dport': 0},
        ['1:NdobDX8PQNJbAyfkWxhtL2Pqp5w=',
         '1:35da1b0d7f0f40d25b0327e45b186d2f63eaa79c',
         '1:OlOWx9psIbBFi7lOCw/4MhlKR9M=']);
})

test('icmp6 4', (t) => {
    assertEqualID(
        {'proto': 'icmp6',
         'saddr': '3ffe:507:0:1:200:86ff:fe05:80da',
         'daddr': '3ffe:507:0:1:260:97ff:fe07:69ea',
         'sport': 3,
         'dport': 0},
        ['1:/OGBt9BN1ofenrmSPWYicpij2Vc=',
         '1:fce181b7d04dd687de9eb9923d66227298a3d957',
         '1:Ij4ZxnC87/MXzhOjvH2vHu7LRmE=']);
})

test('icmp6 5', (t) => {
    assertEqualID(
        {'proto': 58,
         'saddr': '3ffe:507:0:1:200:86ff:fe05:80da',
         'daddr': '3ffe:507:0:1:260:97ff:fe07:69ea',
         'sport': 3,
         'dport': 0},
        ['1:/OGBt9BN1ofenrmSPWYicpij2Vc=',
         '1:fce181b7d04dd687de9eb9923d66227298a3d957',
         '1:Ij4ZxnC87/MXzhOjvH2vHu7LRmE=']);
})

test('tcp 1', (t) => {
    assertEqualID(
        {'proto': 'tcp',
         'saddr': '128.232.110.120',
         'daddr': '66.35.250.204',
         'sport': 34855,
         'dport': 80},
        ['1:LQU9qZlK+B5F3KDmev6m5PMibrg=',
         '1:2d053da9994af81e45dca0e67afea6e4f3226eb8',
         '1:3V71V58M3Ksw/yuFALMcW0LAHvc=']);
})

test('tcp 2', (t) => {
    assertEqualID(
        {'proto': 'tcp',
         'daddr': '128.232.110.120',
         'saddr': '66.35.250.204',
         'dport': 34855,
         'sport': 80},
        ['1:LQU9qZlK+B5F3KDmev6m5PMibrg=',
         '1:2d053da9994af81e45dca0e67afea6e4f3226eb8',
         '1:3V71V58M3Ksw/yuFALMcW0LAHvc=']);
})

test('tcp 3', (t) => {
    assertEqualID(
        {'proto': 'tcp',
         'saddr': '10.0.0.1',
         'daddr': '10.0.0.2',
         'sport': 10,
         'dport': 11569},
        ['1:SXBGMX1lBOwhhoDrZynfROxnhnM=',
         '1:497046317d6504ec218680eb6729df44ec678673',
         '1:HmBRGR+fUyXF4t8WEtal7Y0gEAo=']);
})

test('tcp 4', (t) => {
    assertEqualID(
        {'proto': 6,
         'saddr': '10.0.0.1',
         'daddr': '10.0.0.2',
         'sport': 10,
         'dport': 11569},
        ['1:SXBGMX1lBOwhhoDrZynfROxnhnM=',
         '1:497046317d6504ec218680eb6729df44ec678673',
         '1:HmBRGR+fUyXF4t8WEtal7Y0gEAo=']);
})

test('tcp 5', (t) => {
    assertEqualID(
        {'proto': 6,
         'saddr': '10.0.0.1',
         'daddr': '10.0.0.2',
         'sport': '10',
         'dport': '11569'},
        ['1:SXBGMX1lBOwhhoDrZynfROxnhnM=',
         '1:497046317d6504ec218680eb6729df44ec678673',
         '1:HmBRGR+fUyXF4t8WEtal7Y0gEAo=']);
})

test('udp 1', (t) => {
    assertEqualID(
        {'proto': 'udp',
         'saddr': '192.168.1.52',
         'daddr': '8.8.8.8',
         'sport': 54585,
         'dport': 53},
        ['1:d/FP5EW3wiY1vCndhwleRRKHowQ=',
         '1:77f14fe445b7c22635bc29dd87095e451287a304',
         '1:Q9We8WO3piVF8yEQBNJF4uiSVrI=']);
})

test('udp 2', (t) => {
    assertEqualID(
        {'proto': 'udp',
         'saddr': '8.8.8.8',
         'daddr': '192.168.1.52',
         'sport': 53,
         'dport': 54585},
        ['1:d/FP5EW3wiY1vCndhwleRRKHowQ=',
         '1:77f14fe445b7c22635bc29dd87095e451287a304',
         '1:Q9We8WO3piVF8yEQBNJF4uiSVrI=']);
})

test('udp 3', (t) => {
    assertEqualID(
        {'proto': 17,
         'saddr': '8.8.8.8',
         'daddr': '192.168.1.52',
         'sport': 53,
         'dport': 54585},
        ['1:d/FP5EW3wiY1vCndhwleRRKHowQ=',
         '1:77f14fe445b7c22635bc29dd87095e451287a304',
         '1:Q9We8WO3piVF8yEQBNJF4uiSVrI=']);
})

test('sctp 1', (t) => {
    assertEqualID(
        {'proto': 'sctp',
         'saddr': '192.168.170.8',
         'daddr': '192.168.170.56',
         'sport': 7,
         'dport': 80},
        ['1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=',
         '1:8d0802c5b92efa9346c3c58f6c473f4d2fee4e94',
         '1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU=']);
})

test('sctp 2', (t) => {
    assertEqualID(
        {'proto': 'sctp',
         'daddr': '192.168.170.8',
         'saddr': '192.168.170.56',
         'dport': 7,
         'sport': 80},
        ['1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=',
         '1:8d0802c5b92efa9346c3c58f6c473f4d2fee4e94',
         '1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU=']);
})

test('sctp 3', (t) => {
    assertEqualID(
        {'proto': 132,
         'daddr': '192.168.170.8',
         'saddr': '192.168.170.56',
         'dport': 7,
         'sport': 80},
        ['1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=',
         '1:8d0802c5b92efa9346c3c58f6c473f4d2fee4e94',
         '1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU=']);
})

test('address pairs 1', (t) => {
    assertEqualID(
        {'proto': 46,
         'saddr': '10.1.24.4',
         'daddr': '10.1.12.1'},
        ['1:/nQI4Rh/TtY3mf0R2gJFBkVlgS4=',
         '1:fe7408e1187f4ed63799fd11da0245064565812e',
         '1:BK3BVW3U2eemuwVQVN3zd/GULno=']);
})

test('address pairs 2', (t) => {
    assertEqualID(
        {'proto': 46,
         'daddr': '10.1.24.4',
         'saddr': '10.1.12.1'},
        ['1:/nQI4Rh/TtY3mf0R2gJFBkVlgS4=',
         '1:fe7408e1187f4ed63799fd11da0245064565812e',
         '1:BK3BVW3U2eemuwVQVN3zd/GULno=']);
})

test('input: invalid protocol 1', (t) => {
    assertNullIDWithError(
        {'proto': 'foo' },
        /invalid protocol/);
})

test('input: invalid protocol 2', (t) => {
    assertNullIDWithError(
        {'proto': null },
        /invalid protocol/);
})

test('input: invalid protocol 3', (t) => {
    assertNullIDWithError(
        {'proto': -10,
         'saddr': '128.232.110.120',
         'daddr': '66.35.250.204',
         'sport': 34855,
         'dport': 80},
        /invalid protocol/);
})

test('input: invalid protocol for using ports', (t) => {
    assertNullIDWithError(
        {'proto': 250,
         'saddr': '128.232.110.120',
         'daddr': '66.35.250.204',
         'sport': 34855,
         'dport': 80},
        /invalid protocol .+ for using ports/);
})

test('input: invalid port mix 1', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'dport': 80},
        /invalid port mix/);
})

test('input: invalid port mix 2', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 80},
        /invalid port mix/);
})

test('input: invalid source port 1', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 'foo',
         'dport': 80},
        /invalid source port/);
})

test('input: invalid source port 2', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': -10,
         'dport': 80},
        /invalid source port/);
})

test('input: invalid source port 3', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 100000,
         'dport': 80},
        /invalid source port/);
})

test('input: invalid source port 4', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': {},
         'dport': 80},
        /invalid source port/);
})

test('input: invalid dest port 1', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 80,
         'dport': 'foo'},
        /invalid dest port/);
})

test('input: invalid dest port 2', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 80,
         'dport': -10},
        /invalid dest port/);
})

test('input: invalid dest port 3', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 80,
         'dport': 100000},
        /invalid dest port/);
})

test('input: invalid dest port 4', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 80,
         'dport': {}},
        /invalid dest port/);
})

test('input: invalid source IP address 1', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '123',
         'daddr': '2.3.4.5',
         'sport': 12345,
         'dport': 80},
        /invalid source IP address/);
})

test('input: invalid source IP address 2', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '\x10\x20\x30\x40',
         'daddr': '2.3.4.5',
         'sport': 12345,
         'dport': 80},
        /invalid source IP address/);
})

test('input: invalid source IP address 3', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': 'example.com',
         'daddr': '2.3.4.5',
         'sport': 12345,
         'dport': 80},
        /invalid source IP address/);
})

test('input: invalid dest IP address 1', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '123',
         'sport': 12345,
         'dport': 80},
        /invalid dest IP address/);
})

test('input: invalid dest IP address 2', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '\x10\x20\x30\x40',
         'sport': 12345,
         'dport': 80},
        /invalid dest IP address/);
})

test('input: invalid dest IP address 3', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': 'example.com',
         'sport': 12345,
         'dport': 80},
        /invalid dest IP address/);
})

test('input: invalid seed 1', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 12345,
         'dport': 80},
        /invalid seed value/,
        null);
})

test('input: invalid seed 2', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 12345,
         'dport': 80},
        /invalid seed value/,
        {});
})

test('input: invalid seed 3', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 12345,
         'dport': 80},
        /invalid seed value/,
        -10);
})

test('input: invalid seed 4', (t) => {
    assertNullIDWithError(
        {'proto': 'tcp',
         'saddr': '1.2.3.4',
         'daddr': '2.3.4.5',
         'sport': 12345,
         'dport': 80},
        /invalid seed value/,
        100000);
})
