const testConstant = "value1";
let testCounter = 0;

export const handler = async(event) => {
    testCounter++;

    return {
        counter: testCounter,
        constant: testConstant,
    };
};
