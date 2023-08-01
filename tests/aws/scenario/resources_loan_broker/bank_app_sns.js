
/**
    Each bank will vary its behavior by the following parameters:

    MIN_CREDIT_SCORE - the customer's minimum credit score required to receive a quote from this bank.
    MAX_LOAN_AMOUNT - the maximum amount the bank is willing to lend to a customer.
    BASE_RATE - the minimum rate the bank might give. The actual rate increases for a lower credit score and some randomness.
    BANK_ID - as the loan broker processes multiple responses, knowing which bank supplied the quote will be handy.
*/

function calcRate(amount, term, score, history) {
    console.log("MAX_LOAN_AMOUNT=%d, MIN_CREDIT_SCORE=%d, BASE_RATE=%d", process.env.MAX_LOAN_AMOUNT, process.env.MIN_CREDIT_SCORE, process.env.BASE_RATE)
    console.log("amount=%d, term=%d, score=%d, history=%d", amount, term, score, history)
    if (amount <= process.env.MAX_LOAN_AMOUNT && score >= process.env.MIN_CREDIT_SCORE) {
         console.log("calculating amount...")
        return parseFloat(process.env.BASE_RATE) + history * ((1000 - score) / 100.0);
    }
    console.log("could not calculate amount...")
}

exports.handler = async (event, context) => {
    console.log("Received request for %s", process.env.BANK_ID);
    console.log("Received event:", JSON.stringify(event));

    console.log(event.Records[0].Sns);
    const snsMessage = event.Records[0].Sns.Message;
    const msg = JSON.parse(snsMessage);
    console.log(msg.input);

    const requestId = msg.context.Execution.Id;
    const taskToken = msg.taskToken;
    const bankId = process.env.BANK_ID;
    const data = msg.input;

    console.log("Loan Request over %d at credit score %d", data.Amount, data.Credit.Score);
    const rate = calcRate(data.Amount, data.Term, data.Credit.Score, data.Credit.History);

    if (rate) {
        console.log("rate=%d, bankId=%s, id=%s, taskToken=%s", rate, bankId, requestId, taskToken)

        const quote = {
            rate: rate,
            bankId: bankId,
            id: requestId,
            taskToken: taskToken
        };
        console.log("Offering Loan");

        return quote;
    } else {
        console.log("Rejecting Loan");
    }
};
