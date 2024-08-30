exports.getNewChallenge = function () {
    return [...Array(16)].map(() => Math.random().toString(36)[2]).join('');
}

exports.convertChallenge = function (challenge) {
    return btoa(challenge).replaceAll('=', '');
}

const rpId = process.env.PASSKEY_RPID || "localhost";
exports.getRpId = function () {
    return rpId;
}

const origins = process.env.PASSKEY_ORIGINS.split(' ') || ['http://localhost:3000'];
exports.expectedOrigins = function () {
    return origins;
}