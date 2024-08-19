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

const origins = ['http://localhost:3300', 'https://rapid-charming-vulture.ngrok-free.app', 'android:apk-key-hash:TyBHH9maupZHjVknwsim6o7SjRTAtqI5mZ-jTUc9-hE'];
exports.expectedOrigins = function () {
    return origins;
}