//utils/hashUtils
//Helper klasse
function isBcryptHash(str) {
    if (typeof str !== 'string' || str.length !== 60) return false;
    const bcryptRegex = /^\$2[abyx]\$\d{2}\$[./A-Za-z0-9]{53}$/;
    return bcryptRegex.test(str);
}

module.exports = {
    isBcryptHash
};
