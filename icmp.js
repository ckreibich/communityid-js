const ECHO_REPLY = 0;
const ECHO = 8;
const RTR_ADVERT = 9;
const RTR_SOLICIT = 10;
const TSTAMP = 13;
const TSTAMP_REPLY = 14;
const INFO = 15;
const INFO_REPLY = 16;
const MASK = 17;
const MASK_REPLY = 18;

const TYPE_MAPPER = new Map();
TYPE_MAPPER.set(ECHO, ECHO_REPLY);
TYPE_MAPPER.set(ECHO_REPLY, ECHO);
TYPE_MAPPER.set(TSTAMP, TSTAMP_REPLY);
TYPE_MAPPER.set(TSTAMP_REPLY, TSTAMP);
TYPE_MAPPER.set(INFO, INFO_REPLY);
TYPE_MAPPER.set(INFO_REPLY, INFO);
TYPE_MAPPER.set(RTR_SOLICIT, RTR_ADVERT);
TYPE_MAPPER.set(RTR_ADVERT, RTR_SOLICIT);
TYPE_MAPPER.set(MASK, MASK_REPLY);
TYPE_MAPPER.set(MASK_REPLY, MASK);

exports.get_port_equivalents = function(mtype, mcode) {
    if (! TYPE_MAPPER.has(mtype))
        return [mtype, mcode, true];

    return [mtype, TYPE_MAPPER.get(mtype), false];
}
