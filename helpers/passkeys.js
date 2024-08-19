exports.getNewChallenge = function () {
    return Math.random().toString(36).substring(2);
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