const localCache = {
    counter: 0
};

const handler = async (event, context) => {
    return {
        counter: localCache.counter++
    };
};

module.exports = {handler};
