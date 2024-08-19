exports.getNewChallenge() = function () {
    return Math.random().toString(36).substring(2);
}

exports.convertChallenge(challenge) = function () {
    return btoa(challenge).replaceAll('=', '');
}