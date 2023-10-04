const getRandomInt = (min, max) => {
    return min + Math.floor(Math.random() * (max - min));
};
const min_score = 300;
const max_score = 900;

const getHistoryForSSN = (ssn) => {
    // here should be the logic to retrieve the history of the customer
    if (ssn.startsWith("123")) {
        return 10;
    } else {
        return 13;
    }
};

const getScoreForSSN = (ssn) => {
    // here should be the logic to retrieve the score of the customer
    if (ssn.startsWith("123")) {
        return max_score;
    } else {
        return min_score;
    }
};

exports.handler = async (event) => {

    var ssn_regex = new RegExp("^\\d{3}-\\d{2}-\\d{4}$");


    console.log("received event " + JSON.stringify(event))
    if (ssn_regex.test(event.SSN)) {
        console.log("ssn matches pattern")
        return {
            statusCode: 200,
            request_id: event.RequestId,
            body: {
                SSN: event.SSN,
                score: getScoreForSSN(event.SSN),
                history: getHistoryForSSN(event.SSN),
            },
        };
    } else {
        console.log("ssn not matching pattern")
        return {
            statusCode: 400,
            request_id: event.RequestId,
            body: {
                SSN: event.SSN,
            },
        };
    }
};
