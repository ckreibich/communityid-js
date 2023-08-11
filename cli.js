#! /usr/bin/env node

'use strict';

const { argv, exit } = require('node:process');
const communityid = require('communityid');

let seed = 0;
let use_base64 = true;
let proto, saddr, daddr, sport, dport;
let cid, idx;

function help() {
    console.log('Usage: community-id [-h|--help] [--seed NUM] [--no-base64] [tuple...]');
    console.log();
    console.log('Community ID calculator');
    console.log();
    console.log('Prints the Community ID value for a given flow tuple to stdout.');
    console.log('Use the following order to specify the tuple values:');
    console.log();
    console.log('  [protocol] [source IP] [dest IP] [source port] [dest port]');
    console.log();
    console.log('For example:');
    console.log();
    console.log('  $ community-id tcp 128.232.110.120 66.35.250.204 34855 80');
    console.log('  1:LQU9qZlK+B5F3KDmev6m5PMibrg=');
    console.log();
    console.log('Invalid inputs will lead to an error message on stderr.');
}

if (argv.includes('--help') || argv.includes('-h') || argv.includes('-?')) {
    help();
    exit(0);
}

// Start args from index 2: node itself is [0] and this script is [1].
for (idx = 2; idx < argv.length; idx++) {
    switch (argv.at(idx)) {
    case '--seed':
        if (idx + 1 == argv.length) {
            console.error('The --seed argument needs an integer parameter.')
            exit(1);
        }

        seed = parseInt(argv.at(idx + 1));

        if (isNaN(seed)) {
            console.error('The --seed argument needs an integer parameter.')
            exit(1);
        }

        idx++; // Consume the integer
        break;
    case '--no-base64':
        use_base64 = false;
        break;
    default:
        // We've reached the flow tuple:
        [proto, saddr, daddr, sport, dport] = argv.slice(idx, idx + 5);
        idx = argv.length;
    }
}

if (! proto || ! saddr || ! daddr) {
    help();
    exit(1);
}

if (cid = communityid.calc(proto, saddr, daddr, sport, dport, seed, use_base64)) {
    console.log(cid);
    exit(0);
}

exit(1);
