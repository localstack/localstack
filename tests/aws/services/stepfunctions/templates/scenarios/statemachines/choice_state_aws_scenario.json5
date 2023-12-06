{
  "StartAt": "ChoiceStateX",
  "States": {
    "ChoiceStateX": {
      "Type": "Choice",
      "Choices": [
        {
          "Not": {
            "Variable": "$.type",
            "StringEquals": "Private"
          },
          "Next": "Public"
        },
        {
          "Variable": "$.value",
          "NumericEquals": 0,
          "Next": "ValueIsZero"
        },
        {
          "And": [
            {
              "Variable": "$.value",
              "NumericGreaterThanEquals": 20
            },
            {
              "Variable": "$.value",
              "NumericLessThan": 30
            }
          ],
          "Next": "ValueInTwenties"
        }
      ],
      "Default": "DefaultState"
    },
    "Public": {
      "Type": "Pass",
      "End": true
    },
    "ValueIsZero": {
      "Type": "Pass",
      "End": true
    },
    "ValueInTwenties": {
      "Type": "Pass",
      "End": true
    },
    "DefaultState": {
      "Type": "Fail",
      "Cause": "No Matches!"
    }
  }
}