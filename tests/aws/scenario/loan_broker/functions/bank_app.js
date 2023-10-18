/**
    Each bank will vary its behavior by the following parameters:

    MIN_CREDIT_SCORE - the customer's minimum credit score required to receive a quote from this bank.
    MAX_LOAN_AMOUNT - the maximum amount the bank is willing to lend to a customer.
    BASE_RATE - the minimum rate the bank might give. The actual rate increases for a lower credit score and some randomness.
    BANK_ID - as the loan broker processes multiple responses, knowing which bank supplied the quote will be handy.
 */

function calcRate(amount, term, score, history) {
    if (amount <= process.env.MAX_LOAN_AMOUNT && score >= process.env.MIN_CREDIT_SCORE) {
        return parseFloat(process.env.BASE_RATE) + history * ((1000 - score) / 100.0);
    }
}

exports.handler = async (event) => {
    console.log("Received request for %s", process.env.BANK_ID);
    console.log("Received event:", JSON.stringify(event));

    const amount = event.Amount;
    const term = event.Term;
    const score = event.Credit.Score;
    const history = event.Credit.History;

    const bankId = process.env.BANK_ID;

    console.log("Loan Request over %d at credit score %d", amount, score);
    console.log("Received term: %d, history: %d", term, history);
    const rate = calcRate(amount, term, score, history);
    if (rate) {
        const response = { rate: rate, bankId: bankId };
        console.log(response);
        return response;
    } else {
        console.log("Rejecting Loan");
    }
};
